## Carga del programa  XDP

Ya tenemos escenario y el programa XDP compilado.. Es hora de cargarlo en el Kernel :smirk:. Si usted no sabe de dónde ha salido el programa [``xdp_loader``](https://github.com/davidcawork/TFG/blob/master/src/use_cases/xdp/util/xdp_loader.c), qué nos aporta la librería [``libbpf``](https://github.com/torvalds/linux/tree/master/tools/lib/bpf), o por que no hacemos uso de la herramienta [``iproute2``](https://wiki.linuxfoundation.org/networking/iproute2) para cargar los programas XDP en el Kernel, por favor vuelva al [``case01``](https://github.com/davidcawork/TFG/tree/master/src/use_cases/xdp/case01) donde se intenta abordar todas estas dudas. Si aun así tiene alguna duda extra o considera que no se encuentra del todo explicado póngase en contacto conmigo o mis tutores.

De forma adicional comentar que se va hacer uso del módulo ``netns`` de la herramienta [``iproute2``](https://wiki.linuxfoundation.org/networking/iproute2), si tiene alguna duda sobre este le recomendamos que consulte sus man-pages o vuelva al [``case02``](https://github.com/davidcawork/TFG/tree/master/src/use_cases/xdp/case02) donde se hace una pequeña introducción sobre éste, y su funcionamiento básico para ejecutar comandos "dentro" de una Network Namespace.


```bash

# Anclamos el programa XDP (xdp_pass) en la interfaz veth0, perteneciente a la Network Namespace "uno" 
sudo ip netns exec uno ./xdp_loader -d sta2-wlan0 -F --progsec xdp_filter_packet

# Anclamos el programa XDP en la interfaz uno, perteneciente a la Network Namespace por defecto.
sudo ./xdp_loader -d sta2-wlan0 -F --progsec xdp_filter_packet


```

En este caso de uso aclaremos el programa XDP a validar en la ``veth`` exterior, por lo que las pruebas vendrán induccidas desde "dentro" de la Network Namespace ``uno``. Para anclar el programa hemos hecho uso de nuevo del programa [``xdp_loader``](https://github.com/davidcawork/TFG/blob/master/src/use_cases/xdp/util/xdp_loader.c). Es importante señalar como hemos tenido que anclar un *dummy program* que permite pasar todos los paquetes a la veth destino, esta es una limitación propia por trabajar con ``veth's`` y XDP, de momento se trata de una limitación de implementación, puede que a un corto plazo esta limitación se vea ya superada. Para más inforación sobre esta limitación recomendamos ver la charla de la [Netdev](https://netdevconf.info) llamada **_Veth XDP: XDP for containers_** donde explican con un mayor detalle esta limitación, como abordarla y por que está inducida.  [Enlace a la charla](https://netdevconf.info/0x13/session.html?talk-veth-xdp)


## Comprobación del funcionamiento

La comprobación del funcionamiento del programa XDP anclado a la interfaz ``uno`` se llevará a cabo generando pings desde "dentro" la Network Namespace ``uno`` hacia afuera, para que la interfaz ``uno`` los filtre, analice y nos genere una respuesta. De forma adicional comentar que el programa soporta tanto direccionamiento IPv4 como IPv6, su funcionalidad se vio extendida debido a que la gran parte de la documentación encontrada sobre XDP donde llevan a cabo ejemplos como este hacen uso de direccionamiento IPv6 por lo que, a modo personal, me pareció un buen punto seguir esta corriente ya que el direccionamiento IPv4 se ha agotado este mismo [año](https://www.ripe.net/manage-ips-and-asns/ipv4/ipv4-run-out)  :cold_sweat: ..


```bash

# Lanzamos un ping desde "dentro" Network Namespace hacia la interfaz externa 
sudo ip netns exec uno ping 10.0.0.1

# En una consola aparte lanzamos el programa xdp_stats para ir viendo a tiempo real los códigos de retorno XDP empleados
sudo ./xdp_stats -d uno
```

Si todo funciona correctamente deberíamos ver como los códigos de retorno mayormente empleados son los 
de ``XDP_TX`` siempre y cuando no hayamos detenido el ping desde dentro de la Network
Namespace. El funcionamiento de este programa es muy simple, ya que desde el programa anclado en el Kernel
generamos un mapa donde se van a almacenar las estadísticas sobre los códigos de retorno XDP , y después el programa ``xdp_stats``, programa de espacio de usuario, sabiendo el nombre del mapa BPF donde  se almacenan las estadísticas va a buscarlas y las imprime por pantalla de forma periódica.

## Fuentes

* [Conferencia Veths y XDP](https://netdevconf.info/0x13/session.html?talk-veth-xdp)
* [Mapas eBPF](https://prototype-kernel.readthedocs.io/en/latest/bpf/ebpf_maps.html)
