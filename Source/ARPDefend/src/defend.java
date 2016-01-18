import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Properties;
import java.io.*;
import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;

public class defend {
	public static void process(int index,int timeO) {
		try {
			NetworkInterface[] devices = JpcapCaptor.getDeviceList();
			JpcapCaptor captor1 = JpcapCaptor.openDevice(devices[index], 65535, true, 20);
			//capture only ARP packets
			captor1.setFilter("arp", true);
			System.out.println("Defending started");
			captor1.setNonBlockingMode(false);
			LinkedHashMap<String, String[]> Database = new LinkedHashMap<String, String[]>(); // Database for recording ARPs
			//Get Current time in sec
			Calendar cal = Calendar.getInstance();
			String dateFormat="ss";
			SimpleDateFormat sdf = new SimpleDateFormat(dateFormat);
			String Time=sdf.format(cal.getTime());
			int t_time=Integer.parseInt(Time);
			while(true){
				captor1.processPacket(-1, new PacketHandler(index,Database,timeO));// Capture ARP Packets and process them
				cal = Calendar.getInstance();
				sdf = new SimpleDateFormat(dateFormat);
				Time=sdf.format(cal.getTime());
				int c_time=Integer.parseInt(Time);
				if((c_time-t_time+60)%60> timeO) // Check for non replied ARP requests every timeout
				{
					//System.out.println("entered");
					t_time=c_time;
					Iterator<String> itr = Database.keySet().iterator();
					while (itr.hasNext())
					{
						String ip_temp  = itr.next();
						String[] temporary= new String[3];
						temporary=Database.get(ip_temp);
						int arp_reachable=Integer.parseInt(temporary[2]); 
						int arp_time=Integer.parseInt(temporary[1]);
						int a=c_time - arp_time +60;
						a=a%60; 
						if( arp_reachable==0 && a > timeO )
						{
							System.out.println(ip_temp+" is unreachable!!!!!!!!!!!!!!!!!! and could be a spoofed IP ");
							try {
								FileWriter fstream = new FileWriter("logFile",true);
								BufferedWriter out = new BufferedWriter(fstream);
								out.append(ip_temp+" is unreachable and could be a spoofed IP \n");
								out.close();
								fstream.close();
							} catch (IOException e) {
								e.printStackTrace();
							}
							Database.remove(ip_temp);
							System.out.println("\t"+ip_temp+" was removed from the list ");
						}
					}
				}
			}
		}
		catch (IOException e) {  
			e.printStackTrace();
		}
	}
	public static void main(String[] args) {
		try{
			String file_name = "logFile";
			File file = new File(file_name);
			if (!file.exists())
			{
				file.createNewFile();
				System.out.println("LogFile doesn't exist. LogFile is created");
			}
			Calendar cal = Calendar.getInstance();
			//Get current time
			String dateFormat="yyyy-MM-dd HH:mm:ss";
			SimpleDateFormat sdf = new SimpleDateFormat(dateFormat);
			String Time=sdf.format(cal.getTime());
			FileWriter fstream = new FileWriter(file_name,true);
			BufferedWriter out = new BufferedWriter(fstream);
			out.append("\n Defending started on: "+ Time+ "\n");
			out.close();
			fstream.close();
		}
		catch(Exception e)
		{
			e.printStackTrace();
		}
		int index=0;
		// Parse input arguments
		Properties properties = new Properties();
		for (String arg : args) {
			if (arg.startsWith("-")) {
				int equalIndex = arg.indexOf('=');
				String propertyName = arg.substring(1, equalIndex);
				String propertyValue = arg.substring(equalIndex + 1);
				properties.setProperty(propertyName, propertyValue);
			}
		}
		String intf=(String) properties.get("intf");
		String time_o = (String) properties.get("timeout");
		if(intf!=null)
			index=Integer.parseInt(intf.trim());// 0 for eth0 and 1 for wlan0
		if(time_o!=null)
			process(index,Integer.parseInt(time_o.trim()));
		else
			process(index,5);
	}
}