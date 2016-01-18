import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.LinkedHashMap;

import jpcap.JpcapCaptor;
import jpcap.JpcapSender;
import jpcap.NetworkInterface;
import jpcap.PacketReceiver;
import jpcap.packet.ARPPacket;
import jpcap.packet.EthernetPacket;
import jpcap.packet.Packet;


public class PacketHandler implements PacketReceiver {
	static int intf;
	int timeout;
	LinkedHashMap<String, String[]> Database = new LinkedHashMap<String, String[]>();
	String file_name = "logFile";
	public PacketHandler(int index, LinkedHashMap<String, String[]> database, int timeo) {
		intf=index;
		Database=database;
		timeout=timeo;
	}
	public void receivePacket(Packet packet) { // This is called whenever a packet is received 
		System.out.println(packet);
		//Parsing received packet
		String recPacket = packet.toString();
		String [] Fields = recPacket.split("\\s+");
		String type=Fields[1];
		String mac_src=Fields[2].substring(0, Fields[2].indexOf('('));
		String ip_src=Fields[2].substring(Fields[2].indexOf('/')+1, Fields[2].indexOf(')'));
		NetworkInterface[] devices = JpcapCaptor.getDeviceList(); 
		//get current time
		Calendar cal = Calendar.getInstance();
		String dateFormat="ss";
		SimpleDateFormat sdf = new SimpleDateFormat(dateFormat);
		String Time=sdf.format(cal.getTime());
		if (!(Database.containsKey(ip_src)) && !(ip_src.equals(devices[intf].addresses[0].address.getHostAddress())) && !ip_src.equals("127.0.0.1"))
		{
			// Create new entry for the received ARP
			String [] entry = new String[3];
			entry[0]=mac_src;// MAC address             
			entry[1]=Time;// Time
			entry[2]="0";// Flag ( used to check the existence of the IP )
			Database.put(ip_src, entry); // The key is the source IP address
			System.out.println("\tEntry was added to the list "+ ip_src);
			try {
				int success=SendARPRequest(null,null,InetAddress.getByName(ip_src).getAddress());// Send request to the received IP
				if(success==1)
					System.out.println("\tARP Request is sent to: "+ ip_src);
			} catch (UnknownHostException e) {
				System.out.println(e);
			}
		}
		else// Entry Already exists

		{
			if(!ip_src.equals(devices[intf].addresses[0].address.getHostAddress()))
			{
				System.out.println("\t"+ip_src + " already exists in database");
				String [] temp = Database.get(ip_src);
				//change the flag to say that this ip is reachable
				if(type.equals("REPLY")==true)
					temp[2]="1";
				if(!(mac_src.equals(temp[0]))) //Compare received MAC with saved MAC
				{
					System.out.println("!!!!! ARP POISONING ATTACK!!!!!!\n\t"+ip_src+" has 2 MAC addresses: "+mac_src+" "+ temp[0] );
					try {
						FileWriter fstream = new FileWriter(file_name,true);
						BufferedWriter out = new BufferedWriter(fstream);
						out.append("!!!!! ARP POISONING ATTACK!!!!!!\n\t"+ip_src+" has 2 MAC addresses: "+mac_src+" "+ temp[0] );
						out.close();
						fstream.close();
					} catch (IOException e) {
						e.printStackTrace();
					}
					Database.remove(ip_src); // Remove the entry
				}
			}
		}
	}
	public static int SendARPRequest(byte [] srcIP,byte [] srchard,byte [] destIP){
		// Sends an ARP Request 
		try {
			NetworkInterface[] devices = JpcapCaptor.getDeviceList();
			JpcapSender sender = JpcapSender.openDevice(devices[intf]);
			if(srcIP==null)
			{
				srcIP=devices[intf].addresses[0].address.getAddress();
			}
			if(srchard==null)
				srchard=devices[intf].mac_address;
			byte[] broadcast=new byte[]{(byte)255,(byte)255,(byte)255,(byte)255,(byte)255,(byte)255};
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
}