package DHTapp;
import org.onosproject.net.LinkKey;

import java.io.*;
import java.util.*;

public class DHTRecopilationdata {
    public static int num_elements_topolog(int type_element){
        FileReader input = null;
        BufferedReader bf = null;
        int numLines=0;

        try
            {
            if (type_element == 1)
                input = new FileReader("/home/arppath/Applications/appOnos/HDDP_App_Bidi/RyuFileNodes.txt");
            else
                input = new FileReader("/home/arppath/Applications/appOnos/HDDP_App_Bidi/RyuFileEdges.txt");

            bf = new BufferedReader(input);

            numLines = (int)bf.lines().count();

        } catch (Exception e) {
            e.printStackTrace();
        }
        //if (type_element == 2)
        //    numLines = numLines * 2; // Son bidireccionales por eso el doble
        return numLines;
    }

    public static void Data_generic(long num_sec, int conver_time, int Num_packet_out, int Num_packet_in, int Num_packet_data,
                                    int Num_SDN, int Num_Non_SDN, int Num_Sensors, int Num_enlaces, int num_total_nodos,
                                    int num_total_enlaces, int configureNodes_count)
    {
        FileWriter fichero = null;
        float porcentaje_nodos = 0, porcentaje_enlaces = 0, num_nodos = 0;
        PrintWriter pw = null;

        try
        {
            num_nodos = configureNodes_count;
            Num_Sensors = configureNodes_count - Num_Non_SDN;

            porcentaje_nodos = 100*(num_nodos/(float)num_total_nodos);
            porcentaje_enlaces = 100*((float)(Num_enlaces - (Num_SDN*2))/(float)num_total_enlaces);

            if (porcentaje_nodos >= 0 && porcentaje_enlaces >= 0 && conver_time > 100){
                if (porcentaje_nodos > 100) {
                    porcentaje_nodos = 100;
                }
                else if (porcentaje_nodos <= 0 || Num_Sensors == 0) {
                    porcentaje_enlaces = 0;
                    Num_enlaces = 0;
                }
                if (porcentaje_enlaces > 100) {
                    porcentaje_enlaces = 100;
                }
                fichero = new FileWriter("/home/arppath/data-onos-hddp/datos-onos.txt", true);
                pw = new PrintWriter(fichero);
                pw.println(num_sec + "\t" + conver_time + "\t" + Num_packet_out + "\t" + Num_packet_in + "\t" + Num_packet_data +
                        "\t" + Num_SDN + "\t" + Num_Non_SDN + "\t" + Num_Sensors + "\t" + Num_enlaces + "\t" + porcentaje_nodos +
                        "\t" + porcentaje_enlaces);
            }
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                // Nuevamente aprovechamos el finally para
                // asegurarnos que se cierra el fichero.
                if (null != fichero)
                    fichero.close();
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
    }

    public static void links_topo(Set<LinkKey> configuredLinks, long num_sec)
    {
        FileWriter fichero = null;
        PrintWriter pw = null;
        Map<String, List<String>> topology = new HashMap<String, List<String>>();
        for (LinkKey linkkey: configuredLinks){
            List<String> destinos = new ArrayList<String>();
            if (topology.get(linkkey.src().deviceId().toString()) != null)
                destinos = topology.get(linkkey.src().deviceId().toString());
            destinos.add(linkkey.dst().deviceId().toString());
            topology.put(linkkey.src().deviceId().toString(),destinos);
        }

        try
        {
            fichero = new FileWriter("/home/arppath/data-onos-hddp/topology-onos"+String.valueOf(num_sec)+".txt", true);
            pw = new PrintWriter(fichero);
            Map<String, List<String>> sortedtopology = new TreeMap<>(topology);

            for(Map.Entry<String,List<String>> entry : sortedtopology.entrySet()) {
                String key = entry.getKey();
                pw.print(key + "\t");
                for (int i = 0; i < entry.getValue().size(); i++) {
                    pw.print(entry.getValue().get(i)+"\t");
                }
                pw.print("\n");
            }

        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                // Nuevamente aprovechamos el finally para
                // asegurarnos que se cierra el fichero.
                if (null != fichero)
                    fichero.close();
            } catch (Exception e2) {
                e2.printStackTrace();
            }
        }
    }
}