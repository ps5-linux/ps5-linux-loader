#include "hv_defeat.h"
#include "loader.h"
#include "prepare_resume.h"
#include "utils.h"
#include <unistd.h>

int main(void) {
  if (setup_env()) {
    notify("Something went wrong while initiating.\nPlease make sure your fw "
           "is supported.");
    return -1;
  }
  if (hv_defeat()) {
    notify("Something went wrong while defeating Hypervisor.\nPlease make sure "
           "your fw is supported.");
    return -1;
  }

  if (fetch_linux(&linux_i)) {
    notify("Something went wrong while installing linux files.\n");
    return -1;
  }

  if (prepare_resume()) {
    notify("Something went wrong while preparing resume.\n");
    return -1;
  }

  notify("Finished preparation. Going to rest mode in 5 seconds.\nPlease wait "
         "for the orange light to stop "
         "blinking and then wakeup to Linux :)\n");

  sleep(5);
  enter_rest_mode();

  while (1) {
    sleep(30);
  }

  return 0;
}
