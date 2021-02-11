#include <unistd.h>
#include <seccomp.h>
#include <linux/seccomp.h>
#include <sys/stat.h>
#include <fcntl.h>

int main(int argc, char **argv)
{
  scmp_filter_ctx ctx;
  ctx = seccomp_init(SCMP_ACT_ALLOW);

  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(socket), 0);
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(connect), 0);
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(bind), 0);
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(listen), 0);
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(clone), 0);
  seccomp_rule_add(ctx, SCMP_ACT_KILL, SCMP_SYS(execve), 0);
  seccomp_export_bpf(ctx, STDOUT_FILENO);
}