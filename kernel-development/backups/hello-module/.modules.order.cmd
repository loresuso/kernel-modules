cmd_/home/lore/tesi/kernel-development/hello-module/modules.order := {   echo /home/lore/tesi/kernel-development/hello-module/hello.ko; :; } | awk '!x[$$0]++' - > /home/lore/tesi/kernel-development/hello-module/modules.order