cmd_/home/lore/MasterThesis/kernel-development/attacks-poc/find-all-syms-module/Module.symvers := sed 's/\.ko$$/\.o/' /home/lore/MasterThesis/kernel-development/attacks-poc/find-all-syms-module/modules.order | scripts/mod/modpost     -o /home/lore/MasterThesis/kernel-development/attacks-poc/find-all-syms-module/Module.symvers -e -i Module.symvers   -T -
