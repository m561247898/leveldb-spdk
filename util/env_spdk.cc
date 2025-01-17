// Copyright (c) 2011 The LevelDB Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file. See the AUTHORS file for names of contributors.

#include "db/filename.h"
#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dirent.h>
#include <fcntl.h>
#include <iostream>
#include <limits>
#include <linux/fs.h>
#include <map>
#include <pthread.h>
#include <queue>
#include <set>
#include <stdint.h>
#include <string>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <thread>
#include <type_traits>
#include <unistd.h>
#include <utility>

#include "leveldb/env.h"
#include "leveldb/slice.h"
#include "leveldb/status.h"

#include "port/port.h"
#include "port/thread_annotations.h"
#include "util/env_posix_test_helper.h"
#include "util/posix_logger.h"

#include "spdk/env.h"
#include "spdk/ioat.h"
#include "spdk/nvme.h"
#include "spdk/stdinc.h"
#include "spdk/string.h"

#ifdef NDEBUG
// #define //dprint(...) do { } while (0)
#else
// #define //dprint(...) do { fprintf(stderr, __VA_ARGS__); } while (0)
#endif

namespace leveldb {

#define ROUND_UP(N, S) (((N) + (S)-1) / (S) * (S))
#define ROUND_DOWN(N, S) ((N) / (S) * (S))
#define DIV_ROUND_UP(N, S) (((N) + (S)-1) / (S))

#define LDBFS_MAGIC (0xe51ab1541542020full)

#ifdef LDB_OBJ_SIZE_MB
#if LDB_OBJ_SIZE_MB < 4 || LDB_OBJ_SIZE_MB % 4 != 0
#error "invalid OBJ_SIZE"
#endif
#define OBJ_SIZE (1ULL * LDB_OBJ_SIZE_MB * 1024 * 1024)
#else
#define OBJ_SIZE (4ULL * 1024 * 1024)  // 4 MiB per object
#endif

#define META_SIZE (128)
#define MAX_OBJ_CNT (OBJ_SIZE / META_SIZE)  // maximum objs in LDBFS

#ifdef LDB_OBJ_CNT
#define OBJ_CNT (LDB_OBJ_CNT)
#else
#define OBJ_CNT (4096)
#endif

static_assert(OBJ_CNT <= MAX_OBJ_CNT, "");

#define FS_SIZE (OBJ_SIZE * OBJ_CNT)
#define MAX_NAMELEN (META_SIZE - 8)
#define READ_UNIT (64ULL * 1024)  // Read granularity
static_assert(OBJ_SIZE % READ_UNIT == 0, "");

#define BUF_ALIGN (0x1000)

struct FileMeta {
  union {
    struct {
      uint32_t f_size;
      uint16_t f_reserved;
      uint8_t f_name_len;
    };
    uint64_t sb_magic;
  };
  char f_name[MAX_NAMELEN];
};
static_assert(sizeof(FileMeta) == META_SIZE, "FileMeta size");

struct SuperBlock {
  FileMeta sb_meta[OBJ_CNT];
};

struct ctrlr_entry {
  struct spdk_nvme_ctrlr* ctrlr;
  struct ctrlr_entry* next;
  char name[1024];
};

struct ns_entry {
  struct spdk_nvme_ctrlr* ctrlr;
  struct spdk_nvme_ns* ns;
  struct ns_entry* next;
};

struct ctrlr_entry* g_controllers = NULL;  // guarded by g_ns_mtx
struct ns_entry* g_namespaces = NULL;      // guarded by g_ns_mtx
port::Mutex g_ns_mtx;

int g_sectsize;
int g_nsect;
int g_sect_per_obj;
uint64_t g_dev_size;

std::string g_dbname;

void* g_sbbuf;                            // guarded by g_fs_mtx
SuperBlock* g_sb_ptr;                     // guarded by g_fs_mtx
std::map<std::string, int> g_file_table;  // guarded by g_fs_mtx
std::queue<int> g_free_idx;               // guarded by g_fs_mtx

port::Mutex g_fs_mtx;

struct ThreadInfo {
  bool compaction_thd;
  struct spdk_nvme_qpair* qpair;
  ThreadInfo() {
    compaction_thd = false;
    qpair = spdk_nvme_ctrlr_alloc_io_qpair(g_namespaces->ctrlr, NULL, 0);
  }
  ~ThreadInfo() { spdk_nvme_ctrlr_free_io_qpair(qpair); }
};

thread_local ThreadInfo tinfo;

bool g_vmd = false;

bool probe_cb(void* cb_ctx, const struct spdk_nvme_transport_id* trid,
              struct spdk_nvme_ctrlr_opts* opts) {
  fprintf(stderr, "Attaching to %s\n", trid->traddr);
  opts->io_queue_size = 1;
  return true;
}

void register_ns(struct spdk_nvme_ctrlr* ctrlr, struct spdk_nvme_ns* ns) {
  struct ns_entry* entry;

  if (!spdk_nvme_ns_is_active(ns)) return;

  entry = new ns_entry;
  if (entry == NULL) {
    perror("ns_entry malloc");
    exit(1);
  }

  entry->ctrlr = ctrlr;
  entry->ns = ns;
  entry->next = g_namespaces;
  g_namespaces = entry;
}

void attach_cb(void* cb_ctx, const struct spdk_nvme_transport_id* trid,
               struct spdk_nvme_ctrlr* ctrlr,
               const struct spdk_nvme_ctrlr_opts* opts) {
  int nsid, num_ns;
  struct ctrlr_entry* entry;
  struct spdk_nvme_ns* ns;
  const struct spdk_nvme_ctrlr_data* cdata;

  entry = static_cast<ctrlr_entry*>(malloc(sizeof(struct ctrlr_entry)));
  if (entry == NULL) {
    perror("ctrlr_entry malloc");
    exit(1);
  }

  fprintf(stderr, "Attachedto %s\n", trid->traddr);
  cdata = spdk_nvme_ctrlr_get_data(ctrlr);

  snprintf(entry->name, sizeof(entry->name), "%-20.20s (%-20.20s)", cdata->mn,
           cdata->sn);
  entry->ctrlr = ctrlr;
  entry->next = g_controllers;
  g_controllers = entry;

  num_ns = spdk_nvme_ctrlr_get_num_ns(ctrlr);
  fprintf(stderr, "Using controller %s with %d namespaces.\n", entry->name,
          num_ns);
  for (nsid = 1; nsid <= num_ns; nsid++) {
    ns = spdk_nvme_ctrlr_get_ns(ctrlr, nsid);
    if (ns == NULL) continue;
    register_ns(ctrlr, ns);
  }
}

void cleanup(void) {
  struct ns_entry* ns_entry = g_namespaces;
  struct ctrlr_entry* ctrlr_entry = g_controllers;

  while (ns_entry) {
    struct ns_entry* next = ns_entry->next;
    free(ns_entry);
    ns_entry = next;
  }

  while (ctrlr_entry) {
    struct ctrlr_entry* next = ctrlr_entry->next;
    spdk_nvme_detach(ctrlr_entry->ctrlr);
    free(ctrlr_entry);
    ctrlr_entry = next;
  }
}

void write_complete(void* arg, const struct spdk_nvme_cpl* completion) {
  int* compl_status = static_cast<int*>(arg);
  *compl_status = 1;
  if (spdk_nvme_cpl_is_error(completion)) {
    fprintf(stderr, "spdk write cpl error\n");
    *compl_status = 2;
  }
}

void read_complete(void* arg, const struct spdk_nvme_cpl* completion) {
  int* compl_status = static_cast<int*>(arg);
  *compl_status = 1;
  if (spdk_nvme_cpl_is_error(completion)) {
    fprintf(stderr, "spdk read cpl error\n");
    *compl_status = 2;
  }
}

void flush_complete(void* arg, const struct spdk_nvme_cpl* completion) {
  int* compl_status = static_cast<int*>(arg);
  *compl_status = 1;
  if (spdk_nvme_cpl_is_error(completion)) {
    fprintf(stderr, "spdk flush cpl error\n");
    *compl_status = 2;
  }
}

void write_from_buf(struct spdk_nvme_ns* ns, struct spdk_nvme_qpair* qpair,
                    void* buf, uint64_t lba, uint32_t cnt, int* chk_compl) {
  int rc;

  if (cnt == 0) {
    if (chk_compl != nullptr) *chk_compl = 1;
    return;
  }

  if (chk_compl != nullptr) {
    rc = spdk_nvme_ns_cmd_write(ns, qpair, buf, lba, cnt, write_complete,
                                chk_compl, 0);
    if (rc != 0) {
      fprintf(stderr, "spdk cmd wirte failed\n");
      exit(1);
    }
    return;
  }

  int l_chk_cpl = 0;
  rc = spdk_nvme_ns_cmd_write(ns, qpair, buf, lba, cnt, write_complete,
                              &l_chk_cpl, 0);
  if (rc != 0) {
    fprintf(stderr, "spdk write failed\n");
    exit(1);
  }
  while (!l_chk_cpl) spdk_nvme_qpair_process_completions(qpair, 0);
}

void read_to_buf(struct spdk_nvme_ns* ns, struct spdk_nvme_qpair* qpair,
                 void* buf, uint64_t lba, uint32_t cnt, int* chk_compl) {
  int rc;

  if (cnt == 0) {
    if (chk_compl != nullptr) *chk_compl = 1;
    return;
  }

  if (chk_compl != nullptr) {
    rc = spdk_nvme_ns_cmd_read(ns, qpair, buf, lba, cnt, read_complete,
                               chk_compl, 0);
    if (rc != 0) {
      fprintf(stderr, "spdk cmd read failed\n");
      exit(1);
    }
    return;
  }

  int l_chk_cpl = 0;
  rc = spdk_nvme_ns_cmd_read(ns, qpair, buf, lba, cnt, read_complete,
                             &l_chk_cpl, 0);
  if (rc != 0) {
    fprintf(stderr, "spdk read failed\n");
    exit(1);
  }
  while (!l_chk_cpl) spdk_nvme_qpair_process_completions(qpair, 0);
}

void flush_to_dev(struct spdk_nvme_ns* ns, struct spdk_nvme_qpair* qpair,
                  int* chk_compl) {
  int rc;

  if (chk_compl != nullptr) {
    rc = spdk_nvme_ns_cmd_flush(ns, qpair, flush_complete, chk_compl);
    if (rc != 0) {
      fprintf(stderr, "spdk flush failed\n");
      exit(1);
    }
    return;
  }

  int l_chk_cpl = 0;
  rc = spdk_nvme_ns_cmd_flush(ns, qpair, flush_complete, &l_chk_cpl);
  if (rc != 0) {
    fprintf(stderr, "spdk flush failed\n");
    exit(1);
  }
  while (!l_chk_cpl) spdk_nvme_qpair_process_completions(qpair, 0);
}

void check_completion(struct spdk_nvme_qpair* qpair) {
  spdk_nvme_qpair_process_completions(qpair, 0);
}

void init_spdk(void) {
  int rc;
  struct spdk_env_opts opts;

  spdk_env_opts_init(&opts);
  opts.name = "leveldb";
  opts.shm_id = 0;
  if (spdk_env_init(&opts) < 0) {
    fprintf(stderr, "spdk_env_init failed\n");
    exit(1);
  }

  rc = spdk_nvme_probe(NULL, NULL, probe_cb, attach_cb, NULL);
  if (rc != 0) {
    fprintf(stderr, "spdk_nvme_probe failed\n");
    cleanup();
    exit(1);
  }

  if (g_controllers == NULL) {
    fprintf(stderr, "no NVMe contollers found\n");
    cleanup();
    exit(1);
  }

  if (g_namespaces == NULL) {
    fprintf(stderr, "no namespaces found\n");
    cleanup();
    exit(1);
  }

  struct ns_entry* ns_ent = g_namespaces;

  g_sectsize = spdk_nvme_ns_get_sector_size(ns_ent->ns);
  g_nsect = spdk_nvme_ns_get_num_sectors(ns_ent->ns);
  assert(OBJ_SIZE % g_sectsize == 0);
  g_sect_per_obj = OBJ_SIZE / g_sectsize;
  g_dev_size = spdk_nvme_ns_get_size(ns_ent->ns);

  printf("nvme sector size %d\n", g_sectsize);
  printf("nvme ns sector count %d\n", g_nsect);
  printf("sectors per block %d\n", g_sect_per_obj);
}

namespace {

// Set by EnvPosixTestHelper::SetReadOnlyMMapLimit() and MaxOpenFiles().
int g_open_read_only_file_limit = -1;

constexpr const size_t kWritableFileBufferSize = 65536;

Status PosixError(const std::string& context, int error_number) {
  if (error_number == ENOENT) {
    return Status::NotFound(context, std::strerror(error_number));
  } else {
    return Status::IOError(context, std::strerror(error_number));
  }
}

Slice Basename(const std::string& filename) {
  std::string::size_type separator_pos = filename.rfind('/');
  if (separator_pos == std::string::npos) {
    return Slice(filename);
  }
  return Slice(filename.data() + separator_pos + 1,
               filename.length() - separator_pos - 1);
}

class SpdkSequentialFile final : public SequentialFile {
 public:
  SpdkSequentialFile(std::string filename, char* file_buf, int idx)
      : filename_(filename),
        buf_(file_buf),
        offset_(0),
        idx_(idx),
        size_(g_sb_ptr->sb_meta[idx].f_size) {
    struct ns_entry* ns_ent = g_namespaces;
    struct spdk_nvme_ns* ns = ns_ent->ns;
    struct spdk_nvme_qpair* qpair = tinfo.qpair;
    read_to_buf(ns, qpair, buf_, g_sect_per_obj * idx,
                DIV_ROUND_UP(size_, g_sectsize), nullptr);
  }
  ~SpdkSequentialFile() override { spdk_free(buf_); }

  Status Read(size_t n, Slice* result, char* scratch) override {
    std::cout << "Seq Read filename = ";
    std::cout << filename_ << std::endl;
    Status status;
    n = std::min(n, size_ - offset_);
    if (n == 0) return status;
    memcpy(scratch, buf_ + offset_, n);
    *result = Slice(scratch, n);
    offset_ += n;
    return status;
  }

  Status Skip(uint64_t n) override {
    offset_ += n;
    if (offset_ > OBJ_SIZE) return PosixError(filename_, errno);
    return Status::OK();
  }

 private:
  const std::string filename_;
  char* buf_;
  uint32_t size_;
  uint64_t offset_;
  int idx_;
};

class SpdkRandomAccessFile final : public RandomAccessFile {
 public:
  SpdkRandomAccessFile(std::string filename, char* file_buf, int idx)
      : filename_(std::move(filename)),
        buf_(file_buf),
        idx_(idx),
        size_(g_sb_ptr->sb_meta[idx].f_size) {
    struct ns_entry* ns_ent = g_namespaces;
    struct spdk_nvme_ns* ns = ns_ent->ns;
    struct spdk_nvme_qpair* qpair = tinfo.qpair;
    read_to_buf(ns, qpair, buf_, g_sect_per_obj * idx,
                DIV_ROUND_UP(size_, g_sectsize), nullptr);
  }

  ~SpdkRandomAccessFile() override { spdk_free(buf_); }

  Status Read(uint64_t offset, size_t n, Slice* result,
              char* scratch) override {
    // std::cout << "Random Read filename = ";
    // std::cout << filename_ << std::endl;
    Status status;
    if (offset + n > size_) {
      *result = Slice();
      return PosixError(filename_, EINVAL);
    }
    *result = Slice(buf_ + offset, n);
    return status;
  }

 private:
  const std::string filename_;
  char* buf_;
  uint32_t size_;
  int idx_;
};

class SpdkWritableFile final : public WritableFile {
 public:
  SpdkWritableFile(std::string filename, char* file_buf, int idx, bool truncate)
      : filename_(filename),
        buf_(file_buf),
        idx_(idx),
        closed_(false),
        size_(g_sb_ptr->sb_meta[idx].f_size),
        synced_(size_),
        compl_status_(0) {
    if (truncate) {
      size_ = 0;
      synced_ = 0;
      return;
    }
    struct ns_entry* ns_ent = g_namespaces;
    struct spdk_nvme_ns* ns = ns_ent->ns;
    struct spdk_nvme_qpair* qpair = tinfo.qpair;
    read_to_buf(ns, qpair, buf_, g_sect_per_obj * idx,
                DIV_ROUND_UP(size_, g_sectsize), nullptr);
  }

  ~SpdkWritableFile() override {
    if (!closed_) Close();
    spdk_free(buf_);
  }

  Status Append(const Slice& data) override {
    size_t write_size = data.size();
    const char* write_data = data.data();

    if (size_ + write_size > OBJ_SIZE) {
      fprintf(stderr, "Writable File %s: exceed OBJ SIZE\n", filename_.c_str());
      return Status::IOError("exceed OBJ SIZE");
    }
    memcpy(buf_ + size_, write_data, write_size);
    size_ += write_size;
    return Status::OK();
  }

  Status Close() override {
    FileMeta* meta = &g_sb_ptr->sb_meta[idx_];
    meta->f_size = size_;
    struct ns_entry* ns_ent = g_namespaces;
    struct spdk_nvme_ns* ns = ns_ent->ns;
    struct spdk_nvme_qpair* qpair = tinfo.qpair;
    uint64_t offset = idx_ * META_SIZE;
    char* meta_buf =
        static_cast<char*>(g_sbbuf) + ROUND_DOWN(offset, g_sectsize);
    uint64_t lba = offset / g_sectsize;
    write_from_buf(ns, qpair, meta_buf, lba, 1, nullptr);

    Sync();

    closed_ = true;
    return Status::OK();
  }

  Status Flush() override { return Status::OK(); }

  Status Sync() override {
    // printf("Sync synced_ = %u\n", synced_);
    // printf("Sync size_ = %u\n", size_);
    // printf("Sync g_sb_ptr->sb_meta[idx].f_size = %u\n",
    // g_sb_ptr->sb_meta[idx_].f_size); std::cout << "The file is: " <<
    // filename_ << std::endl;
    if (synced_ == size_) return Status::OK();
    struct ns_entry* ns_ent = g_namespaces;
    struct spdk_nvme_ns* ns = ns_ent->ns;
    struct spdk_nvme_qpair* qpair = tinfo.qpair;
    char* target_buf = buf_ + ROUND_DOWN(synced_, g_sectsize);
    uint64_t lba = g_sect_per_obj * idx_ + synced_ / g_sectsize;
    uint32_t cnt = DIV_ROUND_UP(size_, g_sectsize) - synced_ / g_sectsize;
    write_from_buf(ns, qpair, target_buf, lba, cnt, nullptr);
    flush_to_dev(ns, qpair, nullptr);
    synced_ = size_;
    return Status::OK();
  }

  Status AsyncSync() override {
    assert(tinfo.compaction_thd);
    if (synced_ == size_) return Status::OK();
    struct ns_entry* ns_ent = g_namespaces;
    struct spdk_nvme_ns* ns = ns_ent->ns;
    struct spdk_nvme_qpair* qpair = tinfo.qpair;
    char* target_buf = buf_ + ROUND_DOWN(synced_, g_sectsize);
    uint64_t lba = g_sect_per_obj * idx_ + synced_ / g_sectsize;
    uint32_t cnt = DIV_ROUND_UP(size_, g_sectsize) - synced_ / g_sectsize;

    write_from_buf(ns, qpair, target_buf, lba, cnt, &compl_status_);
    synced_ = size_;
    return Status::OK();
  }

  bool CheckSync() override {
    assert(tinfo.compaction_thd);
    struct ns_entry* ns_ent = g_namespaces;
    struct spdk_nvme_qpair* qpair = tinfo.qpair;
    if (compl_status_ == 0) check_completion(qpair);
    return compl_status_ > 0 ? true : false;
  }

  Status FlushSync() override {
    assert(tinfo.compaction_thd);
    struct ns_entry* ns_ent = g_namespaces;
    struct spdk_nvme_ns* ns = ns_ent->ns;
    struct spdk_nvme_qpair* qpair = tinfo.qpair;
    flush_to_dev(ns, qpair, nullptr);
    return Status::OK();
  }

 private:
  const std::string filename_;
  char* buf_;
  uint32_t size_;
  uint32_t synced_;
  int idx_;
  bool closed_;
  int compl_status_;
};

int LockOrUnlock(int fd, bool lock) {
  errno = 0;
  struct ::flock file_lock_info;
  std::memset(&file_lock_info, 0, sizeof(file_lock_info));
  file_lock_info.l_type = (lock ? F_WRLCK : F_UNLCK);
  file_lock_info.l_whence = SEEK_SET;
  file_lock_info.l_start = 0;
  file_lock_info.l_len = 0;  // Lock/unlock entire file.
  return ::fcntl(fd, F_SETLK, &file_lock_info);
}

// Instances are thread-safe because they are immutable.
class PosixFileLock : public FileLock {
 public:
  PosixFileLock(int fd, std::string filename)
      : fd_(fd), filename_(std::move(filename)) {}

  int fd() const { return fd_; }
  const std::string& filename() const { return filename_; }

 private:
  const int fd_;
  const std::string filename_;
};

// Tracks the files locked by PosixEnv::LockFile().
//
// We maintain a separate set instead of relying on fcntrl(F_SETLK) because
// fcntl(F_SETLK) does not provide any protection against multiple uses from the
// same process.
//
// Instances are thread-safe because all member data is guarded by a mutex.
class PosixLockTable {
 public:
  bool Insert(const std::string& fname) LOCKS_EXCLUDED(mu_) {
    mu_.Lock();
    bool succeeded = locked_files_.insert(fname).second;
    mu_.Unlock();
    return succeeded;
  }
  void Remove(const std::string& fname) LOCKS_EXCLUDED(mu_) {
    mu_.Lock();
    locked_files_.erase(fname);
    mu_.Unlock();
  }

 private:
  port::Mutex mu_;
  std::set<std::string> locked_files_ GUARDED_BY(mu_);
};

class PosixEnv : public Env {
 public:
  PosixEnv();
  ~PosixEnv() override {
    static char msg[] = "PosixEnv singleton destroyed. Unsupported behavior!\n";
    std::fwrite(msg, 1, sizeof(msg), stderr);
    std::abort();
  }

  Status NewSequentialFile(const std::string& filename,
                           SequentialFile** result) override {
    // dprint("NewSequentialFile %s\n", filename.c_str());

    std::string basename = Basename(filename).ToString();
    g_fs_mtx.Lock();
    if (!g_file_table.count(basename)) {
      g_fs_mtx.Unlock();
      return PosixError(filename, ENOENT);
    }
    int idx = g_file_table[basename];
    g_fs_mtx.Unlock();

    char* fbuf = static_cast<char*>(
        spdk_malloc(OBJ_SIZE, BUF_ALIGN, static_cast<uint64_t*>(NULL),
                    SPDK_ENV_SOCKET_ID_ANY, SPDK_MALLOC_DMA));
    if (fbuf == NULL) {
      fprintf(stderr, "NewSequentialFile malloc failed\n");
      exit(1);
    }
    *result = new SpdkSequentialFile(basename, fbuf, idx);

    return Status::OK();
  }

  Status NewRandomAccessFile(const std::string& filename,
                             RandomAccessFile** result) override {
    // dprint("NewRandomAccessFile %s\n", filename.c_str());

    std::string basename = Basename(filename).ToString();
    char* fbuf = nullptr;

    g_fs_mtx.Lock();
    if (!g_file_table.count(basename)) {
      g_fs_mtx.Unlock();
      return PosixError(filename, ENOENT);
    }
    int idx = g_file_table[basename];

    g_fs_mtx.Unlock();

    fbuf = static_cast<char*>(
        spdk_malloc(OBJ_SIZE, BUF_ALIGN, static_cast<uint64_t*>(NULL),
                    SPDK_ENV_SOCKET_ID_ANY, SPDK_MALLOC_DMA));
    if (fbuf == NULL) {
      fprintf(stderr, "NewRandomAccessFile malloc failed\n");
      exit(1);
    }
    *result = new SpdkRandomAccessFile(basename, fbuf, idx);

    return Status::OK();
  }

  Status NewWritableFile(const std::string& filename,
                         WritableFile** result) override {
    // dprint("NewWritableFile %s\n", filename.c_str());

    std::string basename = Basename(filename).ToString();

    g_fs_mtx.Lock();
    int idx;
    if (!g_file_table.count(basename)) {
      if (g_free_idx.empty()) {
        fprintf(stderr, "out of blocks\n");
        exit(1);
      }
      idx = g_free_idx.front();
      g_free_idx.pop();
      g_file_table.insert({basename, idx});

      FileMeta* meta = &g_sb_ptr->sb_meta[idx];
      strcpy(meta->f_name, basename.c_str());
      meta->f_name_len = basename.size();
      meta->f_size = 0;
      meta->f_reserved = 0;
    } else {
      idx = g_file_table[basename];
    }
    g_fs_mtx.Unlock();

    char* fbuf = static_cast<char*>(
        spdk_malloc(OBJ_SIZE, BUF_ALIGN, static_cast<uint64_t*>(NULL),
                    SPDK_ENV_SOCKET_ID_ANY, SPDK_MALLOC_DMA));
    if (fbuf == NULL) {
      fprintf(stderr, "NewWritableFile malloc failed\n");
      exit(1);
    }
    *result = new SpdkWritableFile(basename, fbuf, idx, true);

    return Status::OK();
  }

  // if want to reuse Manifest
  // useless
  Status NewAppendableFile(const std::string& filename,
                           WritableFile** result) override {
    // dprint("NewAppendableFile %s\n", filename.c_str());
    std::cout << "Newappendable  filename = ";
    std::cout << filename << std::endl;
    std::string basename = Basename(filename).ToString();

    g_fs_mtx.Lock();
    int idx;
    if (!g_file_table.count(basename)) {
      if (g_free_idx.empty()) {
        fprintf(stderr, "out of blocks\n");
        exit(1);
      }
      idx = g_free_idx.front();
      g_free_idx.pop();
      g_file_table.insert({basename, idx});

      FileMeta* meta = &g_sb_ptr->sb_meta[idx];
      strcpy(meta->f_name, basename.c_str());
      meta->f_name_len = basename.size();
      meta->f_size = 0;
      meta->f_reserved = 0;
    } else {
      idx = g_file_table[basename];
    }
    g_fs_mtx.Unlock();

    char* fbuf = static_cast<char*>(
        spdk_malloc(OBJ_SIZE, BUF_ALIGN, static_cast<uint64_t*>(NULL),
                    SPDK_ENV_SOCKET_ID_ANY, SPDK_MALLOC_DMA));
    if (fbuf == NULL) {
      fprintf(stderr, "NewAppendableFile malloc failed\n");
      exit(1);
    }

    *result = new SpdkWritableFile(basename, fbuf, idx, false);

    return Status::OK();
  }

  bool FileExists(const std::string& filename) override {
    std::string basename = Basename(filename).ToString();
    bool ret;
    g_fs_mtx.Lock();
    ret = g_file_table.count(basename);
    g_fs_mtx.Unlock();

    return ret;
  }

  // useless?
  Status GetChildren(const std::string& directory_path,
                     std::vector<std::string>* result) override {
    result->clear();

    g_fs_mtx.Lock();
    for (auto& it : g_file_table) result->emplace_back(it.first);
    g_fs_mtx.Unlock();

    return Status::OK();
  }

  Status DeleteFile(const std::string& filename) override {
    // dprint("DeleteFile %s\n", filename.c_str());

    std::string basename = Basename(filename).ToString();
    g_fs_mtx.Lock();

    if (!g_file_table.count(basename)) {
      g_fs_mtx.Unlock();
      return PosixError(filename, ENOENT);
    }

    int idx = g_file_table[basename];
    FileMeta* meta = &g_sb_ptr->sb_meta[idx];

    meta->f_size = 0;
    meta->f_name_len = 0;
    meta->f_reserved = 0;
    meta->f_name[0] = '\0';

    struct ns_entry* ns_ent = g_namespaces;
    struct spdk_nvme_ns* ns = ns_ent->ns;
    struct spdk_nvme_qpair* qpair = tinfo.qpair;
    uint64_t offset = idx * META_SIZE;  // in bytes
    void* buf = static_cast<char*>(g_sbbuf) + ROUND_DOWN(offset, g_sectsize);
    write_from_buf(ns, qpair, buf, offset / g_sectsize, 1, nullptr);

    g_free_idx.push(idx);
    g_file_table.erase(basename);

    g_fs_mtx.Unlock();

    return Status::OK();
  }

  // initialize internal filesystem here
  Status CreateDir(const std::string& dirname) override {
    if (g_dbname == "") {
      g_dbname = dirname;
      g_sbbuf = spdk_zmalloc(OBJ_SIZE, BUF_ALIGN, nullptr,
                             SPDK_ENV_SOCKET_ID_ANY, SPDK_MALLOC_DMA);
      if (g_sbbuf == nullptr) {
        fprintf(stderr, "spdk zmalloc failed\n");
        exit(1);
      }

      g_fs_mtx.Lock();

      struct ns_entry* ns_ent = g_namespaces;
      struct spdk_nvme_ns* ns = ns_ent->ns;
      struct spdk_nvme_qpair* qpair = tinfo.qpair;
      read_to_buf(ns, qpair, g_sbbuf, 0, g_sect_per_obj, nullptr);
      g_sb_ptr = reinterpret_cast<SuperBlock*>(g_sbbuf);
      FileMeta* sb_meta = &g_sb_ptr->sb_meta[0];
      if (sb_meta->sb_magic == LDBFS_MAGIC) {
        // dprint("ldbfs found\n");
        for (int i = 1; i < OBJ_CNT; i++) {
          FileMeta* meta_ent = &g_sb_ptr->sb_meta[i];
          if (meta_ent->f_name_len == 0) {
            g_free_idx.push(i);
          } else {
            g_file_table.insert({meta_ent->f_name, i});
          }
        }
      } else {
        memset(g_sbbuf, 0, sizeof(SuperBlock));
        sb_meta->sb_magic = LDBFS_MAGIC;
        for (int i = 1; i < OBJ_CNT; i++) {
          g_free_idx.push(i);
        }
        write_from_buf(ns, qpair, g_sbbuf, 0, g_sect_per_obj, nullptr);
      }
      g_fs_mtx.Unlock();
    }

    return Status::OK();
  }

  Status DeleteDir(const std::string& dirname) override {
    if (g_dbname != "") {
      struct ns_entry* ns_ent = g_namespaces;
      struct spdk_nvme_ns* ns = ns_ent->ns;
      struct spdk_nvme_qpair* qpair = tinfo.qpair;
      memset(g_sbbuf, 0, sizeof(SuperBlock));
      write_from_buf(ns, qpair, g_sbbuf, 0, g_sect_per_obj, nullptr);

      g_dbname = "";
      spdk_free(g_sbbuf);
      g_sbbuf = nullptr;
      g_file_table.clear();
      while (!g_free_idx.empty()) {
        g_free_idx.pop();
      }
    } else {
      struct ns_entry* ns_ent = g_namespaces;
      struct spdk_nvme_ns* ns = ns_ent->ns;
      struct spdk_nvme_qpair* qpair = tinfo.qpair;
      g_sbbuf = spdk_zmalloc(OBJ_SIZE, BUF_ALIGN, nullptr,
                             SPDK_ENV_SOCKET_ID_ANY, SPDK_MALLOC_DMA);
      write_from_buf(ns, qpair, g_sbbuf, 0, g_sect_per_obj, nullptr);
      spdk_free(g_sbbuf);
    }
    return Status::OK();
  }

  // useless
  Status GetFileSize(const std::string& filename, uint64_t* size) override {
    // dprint("GetFileSize %s\n", filename.c_str());

    std::string basename = Basename(filename).ToString();
    g_fs_mtx.Lock();
    if (!g_file_table.count(basename)) {
      g_fs_mtx.Unlock();
      return PosixError(filename, ENOENT);
    }

    int idx = g_file_table[basename];

    FileMeta* meta = &g_sb_ptr->sb_meta[idx];

    *size = meta->f_size;

    g_fs_mtx.Unlock();

    return Status::OK();
  }

  Status RenameFile(const std::string& from, const std::string& to) override {
    // dprint("RenameFile %s %s\n", from.c_str(), to.c_str());

    std::string basename_from = Basename(from).ToString();
    std::string basename_to = Basename(to).ToString();
    g_fs_mtx.Lock();

    if (!g_file_table.count(basename_from)) {
      g_fs_mtx.Unlock();
      return PosixError(from, ENOENT);
    }

    g_fs_mtx.Unlock();
    DeleteFile(to);  // ignore error
    g_fs_mtx.Lock();

    int idx = g_file_table[basename_from];
    FileMeta* meta = &g_sb_ptr->sb_meta[idx];

    meta->f_name_len = basename_to.size();
    strcpy(meta->f_name, basename_to.c_str());

    struct ns_entry* ns_ent = g_namespaces;
    struct spdk_nvme_ns* ns = ns_ent->ns;
    struct spdk_nvme_qpair* qpair = tinfo.qpair;
    uint64_t offset = idx * META_SIZE;  // in bytes
    void* buf = static_cast<char*>(g_sbbuf) + ROUND_DOWN(offset, g_sectsize);
    write_from_buf(ns, qpair, buf, offset / g_sectsize, 1, nullptr);

    g_file_table[basename_to] = g_file_table[basename_from];
    g_file_table.erase(basename_from);

    g_fs_mtx.Unlock();

    return Status::OK();
  }

  Status LockFile(const std::string& filename, FileLock** lock) override {
    int fd = 0;
    *lock = new PosixFileLock(fd, filename);
    return Status::OK();
  }

  Status UnlockFile(FileLock* lock) override {
    PosixFileLock* posix_file_lock = static_cast<PosixFileLock*>(lock);
    delete posix_file_lock;
    return Status::OK();
  }

  void Schedule(void (*background_work_function)(void* background_work_arg),
                void* background_work_arg) override;

  void StartThread(void (*thread_main)(void* thread_main_arg),
                   void* thread_main_arg) override;

  Status GetTestDirectory(std::string* result) override { return Status::OK(); }

  Status NewLogger(const std::string& filename, Logger** result) override {
    std::FILE* fp = std::fopen(filename.c_str(), "w");
    if (fp == nullptr) {
      *result = nullptr;
      return PosixError(filename, errno);
    } else {
      *result = new PosixLogger(fp);
      return Status::OK();
    }
  }

  uint64_t NowMicros() override {
    static constexpr uint64_t kUsecondsPerSecond = 1000000;
    struct ::timeval tv;
    ::gettimeofday(&tv, nullptr);
    return static_cast<uint64_t>(tv.tv_sec) * kUsecondsPerSecond + tv.tv_usec;
  }

  void SleepForMicroseconds(int micros) override { ::usleep(micros); }

 private:
  void BackgroundThreadMain();

  static void BackgroundThreadEntryPoint(PosixEnv* env) {
    env->BackgroundThreadMain();
  }

  // Stores the work item data in a Schedule() call.
  //
  // Instances are constructed on the thread calling Schedule() and used on the
  // background thread.
  //
  // This structure is thread-safe beacuse it is immutable.
  struct BackgroundWorkItem {
    explicit BackgroundWorkItem(void (*function)(void* arg), void* arg)
        : function(function), arg(arg) {}

    void (*const function)(void*);
    void* const arg;
  };

  port::Mutex background_work_mutex_;
  port::CondVar background_work_cv_ GUARDED_BY(background_work_mutex_);
  bool started_background_thread_ GUARDED_BY(background_work_mutex_);

  std::queue<BackgroundWorkItem> background_work_queue_
      GUARDED_BY(background_work_mutex_);

  PosixLockTable locks_;  // Thread-safe.
};

}  // namespace

PosixEnv::PosixEnv()
    : background_work_cv_(&background_work_mutex_),
      started_background_thread_(false) {
  g_ns_mtx.Lock();
  init_spdk();
  g_ns_mtx.Unlock();
}

void PosixEnv::Schedule(
    void (*background_work_function)(void* background_work_arg),
    void* background_work_arg) {
  background_work_mutex_.Lock();

  // Start the background thread, if we haven't done so already.
  if (!started_background_thread_) {
    started_background_thread_ = true;
    std::thread background_thread(PosixEnv::BackgroundThreadEntryPoint, this);
    background_thread.detach();
  }

  // If the queue is empty, the background thread may be waiting for work.
  if (background_work_queue_.empty()) {
    background_work_cv_.Signal();
  }

  background_work_queue_.emplace(background_work_function, background_work_arg);
  background_work_mutex_.Unlock();
}

void PosixEnv::BackgroundThreadMain() {
  tinfo.compaction_thd = true;
  while (true) {
    background_work_mutex_.Lock();

    // Wait until there is work to be done.
    while (background_work_queue_.empty()) {
      background_work_cv_.Wait();
    }

    assert(!background_work_queue_.empty());
    auto background_work_function = background_work_queue_.front().function;
    void* background_work_arg = background_work_queue_.front().arg;
    background_work_queue_.pop();

    background_work_mutex_.Unlock();
    background_work_function(background_work_arg);
  }
}

namespace {

// Wraps an Env instance whose destructor is never created.
//
// Intended usage:
//   using PlatformSingletonEnv = SingletonEnv<PlatformEnv>;
//   void ConfigurePosixEnv(int param) {
//     PlatformSingletonEnv::AssertEnvNotInitialized();
//     // set global configuration flags.
//   }
//   Env* Env::Default() {
//     static PlatformSingletonEnv default_env;
//     return default_env.env();
//   }
template <typename EnvType>
class SingletonEnv {
 public:
  SingletonEnv() {
#if !defined(NDEBUG)
    env_initialized_.store(true, std::memory_order::memory_order_relaxed);
#endif  // !defined(NDEBUG)
    static_assert(sizeof(env_storage_) >= sizeof(EnvType),
                  "env_storage_ will not fit the Env");
    static_assert(alignof(decltype(env_storage_)) >= alignof(EnvType),
                  "env_storage_ does not meet the Env's alignment needs");
    new (&env_storage_) EnvType();
  }
  ~SingletonEnv() = default;

  SingletonEnv(const SingletonEnv&) = delete;
  SingletonEnv& operator=(const SingletonEnv&) = delete;

  Env* env() { return reinterpret_cast<Env*>(&env_storage_); }

  static void AssertEnvNotInitialized() {
#if !defined(NDEBUG)
    assert(!env_initialized_.load(std::memory_order::memory_order_relaxed));
#endif  // !defined(NDEBUG)
  }

 private:
  typename std::aligned_storage<sizeof(EnvType), alignof(EnvType)>::type
      env_storage_;
#if !defined(NDEBUG)
  static std::atomic<bool> env_initialized_;
#endif  // !defined(NDEBUG)
};

#if !defined(NDEBUG)
template <typename EnvType>
std::atomic<bool> SingletonEnv<EnvType>::env_initialized_;
#endif  // !defined(NDEBUG)

using PosixDefaultEnv = SingletonEnv<PosixEnv>;

}  // namespace

void PosixEnv::StartThread(void (*thread_main)(void* thread_main_arg),
                           void* thread_main_arg) {
  std::thread new_thread(thread_main, thread_main_arg);
  new_thread.detach();
}

void EnvPosixTestHelper::SetReadOnlyFDLimit(int limit) {
  PosixDefaultEnv::AssertEnvNotInitialized();
  g_open_read_only_file_limit = limit;
}

void EnvPosixTestHelper::SetReadOnlyMMapLimit(int limit) {}

Env* Env::Default() {
  static PosixDefaultEnv env_container;
  return env_container.env();
}

}  // namespace leveldb
