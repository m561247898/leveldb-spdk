#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/sem.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>

#include "spdk/env.h"
#include "spdk/ioat.h"
#include "spdk/nvme.h"
#include "spdk/stdinc.h"
#include "spdk/string.h"
#define BUF_ALIGN (0x1000)
#define OBJ_SIZE (8ULL * 1024 * 1024)  // 4 MiB per object
int g_sectsize;
int g_nsect;
int g_sect_per_obj;
uint64_t g_dev_size;
void* g_sbbuf;
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
void write_complete(void* arg, const struct spdk_nvme_cpl* completion) {
  int* compl_status = static_cast<int*>(arg);
  *compl_status = 1;
  if (spdk_nvme_cpl_is_error(completion)) {
    fprintf(stderr, "spdk write cpl error\n");
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
int main(int argc, char* argv[]) {
  init_spdk();
  struct ns_entry* ns_ent = g_namespaces;
  struct spdk_nvme_ns* ns = ns_ent->ns;
  struct spdk_nvme_qpair* qpair =
      spdk_nvme_ctrlr_alloc_io_qpair(g_namespaces->ctrlr, NULL, 0);
  int size = (4 * 1024 * 1024);
  int write_sectors = size / 512;
  int write_start = 0;
  for (int i = 0; i < 1000; i++) {
    g_sbbuf = spdk_zmalloc(size, BUF_ALIGN, nullptr, SPDK_ENV_SOCKET_ID_ANY,
                           SPDK_MALLOC_DMA);
    write_from_buf(ns, qpair, (char*)g_sbbuf, write_start, write_sectors, nullptr);
    write_start += write_sectors;

  }
  printf("write success!\n");
}
