cmd_/home/lore/MasterThesis/kernel-development/find-all-syms-module/modules.order := {   echo /home/lore/MasterThesis/kernel-development/find-all-syms-module/finder.ko; :; } | awk '!x[$$0]++' - > /home/lore/MasterThesis/kernel-development/find-all-syms-module/modules.order
