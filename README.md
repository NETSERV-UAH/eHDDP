# eHDDP
enhanced Hybrid Domain Discovery Protocol 
Copyright (C) 2020 Joaquín Álvarez-Horcajo(1), Isaias Martinez-Yelmo(1), Juan Antonio-Carral (1) and Diego Lopez-Pajares;


                     (1) GIST, University of Alcala, Spain.
                     
                     (2) Polytechnic University of Madrid, Spain.


This repository is made up of the following elements:

1.- Onos-eHDDP-APP: Here is the ONOS application code capable of collecting the topology information contained in the eHDDP packets that arrive at the controller.

2.- eHDDP-Mote: Here is the python code of the elements used as wireless devices in the eHDDP simulations.

3.- eHDDP-switch: Here is the code of the eHDDP switch. This switch is based on the BOFUSS switch software.

4.- Filter_packet_xdp: Here is the XDP code in charge of discarding packets when two motes are not within range.

5.- mn-wifi-uah: Here is the modified wifi-mininet code. This code take into account the position of the motes and their ranges in the transmission of the packets.
