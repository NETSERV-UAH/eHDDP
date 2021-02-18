# eHDDP: enhanced Hybrid Domain Discovery Protocol 

Copyright (C) 2020 Isaias Martinez-Yelmo(1), Joaquín Álvarez-Horcajo(1), Juan Antonio-Carral (1) and Diego Lopez-Pajares (2);


                     (1) GIST, University of Alcala, Spain.
                     
                     (2) Polytechnic University of Madrid, Spain.



## XDP load program to accept and reject packets

This program is implemented using XDP and allows accepting and rejecting incoming packets using the source MAC address as the discriminant parameter
To link this program with one interface we will follow the next examples
```bash

# Associate the XDP program (xdp loader) into the intf.name interface
./xdp_loader -d [intf.name] -F --progsec xdp_filter_packet --auto-mode

# Now we insert the rejected [-R] and accepted [-L] MAC address lists into the intf.name interface [--dev].
./prog_user --dev [intf.name] -R [rejected MAC addr list] -L [Accepted MAC addr list]

```

