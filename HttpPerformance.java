import java.util.HashMap;
import java.util.*;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Http;

class FileInfo{
	long numTcp;
	String httpVersion;
	long numPackets;
	long rawBytes;
	long timeTaken;
}

public class HttpPerformance {
     static List<FileInfo> fileInfoList;
     long numTcp;
 	 String httpVersion;
 	 long numPackets;
 	 long rawBytes;
 	 //long timeTaken;
 	 
 	boolean synSeen, synAckSeen; 
 	List<Long> fileTime = new ArrayList<Long>();
 	
 	
	public static void main(String[] args) {
		HttpPerformance obj = new HttpPerformance();
		fileInfoList = new ArrayList<FileInfo>();
		obj.doWork("http_8092.pcap");
		obj.doWork("http_8093.pcap");
		obj.doWork("http_8094.pcap");	
		
		FileInfo fileinfo = fileInfoList.get(0);
		System.out.println("File 1 : http_8092.pcap Information");
		System.out.println("Number of Packets : "+fileinfo.numPackets);
		System.out.println("Raw Bytes  : "+fileinfo.rawBytes);
		System.out.println("Number of TCP flows : "+fileinfo.numTcp);
		System.out.println("Time Takem : " +fileinfo.timeTaken);
		
		System.out.println();
		
		 fileinfo = fileInfoList.get(1);
		System.out.println("File 1 : http_8093.pcap Information");
		System.out.println("Number of Packets : "+fileinfo.numPackets);
		System.out.println("Raw Bytes  : "+fileinfo.rawBytes);
		System.out.println("Number of TCP flows : "+fileinfo.numTcp);
		System.out.println("Time Takem : " +fileinfo.timeTaken);
		
		System.out.println();
		
		fileinfo = fileInfoList.get(2);
		System.out.println("File 1 : http_8094.pcap Information");
		System.out.println("Number of Packets : "+fileinfo.numPackets);
		System.out.println("Raw Bytes  : "+fileinfo.rawBytes);
		System.out.println("Number of TCP flows : "+fileinfo.numTcp);
		System.out.println("Time Takem : " +fileinfo.timeTaken);
		
		System.out.println();
		
		System.out.println("Answer to the C.2 Part: ");
		System.out.println("File 1 is using HTTP 1.0  --> bacause a lot of tcp flows is a sign of Http 1.0");
		System.out.println("File 2 is using HTTP 1.1  --> bacause medium number of  flows is a sign of Http 1.1");
		System.out.println("File 3 is using HTTP 2.0  --> bacause a sigle persistence tcp flow is a sign of Http 2.0");
		
      
		System.out.println();
		
		System.out.println("Answer to the C.3 Part :");
		
		System.out.println("Http 1.0 loaded the site fastest");
		System.out.println("Http 2.0 loaded the site slowest");
		
		System.out.println();
		System.out.println("Http 1.0 sent the  most number of packets");
		System.out.println("Http 2.0 sent the  least number of packets");
		
		
		System.out.println();
		System.out.println("Http 1.1 sent the most raw bytes");
		System.out.println("Http 2.0 sent the  least number of RawBytes");
		
	}
	
	public void doWork(String fi) {
		String FILENAME = fi;
		StringBuilder errbuf = new StringBuilder();
		Pcap pcap = Pcap.openOffline(FILENAME, errbuf);
		if (pcap == null) {
			System.err.println(errbuf);
			return;
		}
		pcap.loop(-1, new JPacketHandler<StringBuilder>() {
              	public void nextPacket(JPacket packet, StringBuilder errbuf) {
					if (packet.hasHeader(Tcp.ID)) {
						
						numPackets++;
						fileTime.add(packet.getCaptureHeader().timestampInMillis());
						rawBytes+= packet.size();
						long srcPort = 0;
						srcPort = (long) packet.getUByte(34);
						srcPort =  (long) (srcPort * Math.pow(16, 2)  + packet.getUByte(35));
						//System.out.println("srcPort: " + srcPort);
					
						long dstPort = 0;
						dstPort = (long) packet.getUByte(36);
						dstPort =  (long) (dstPort * Math.pow(16, 2)  + packet.getUByte(37));
						//System.out.println("dstPort: " + dstPort);
						
						long seqN = 0;
						seqN = (long) packet.getUByte(38);
						seqN =  (long) (seqN * Math.pow(16, 2)  + packet.getUByte(39));
						seqN =  (long) (seqN * Math.pow(16, 2)  + packet.getUByte(40));
						seqN =  (long) (seqN * Math.pow(16, 2)  + packet.getUByte(41));
						//System.out.println("SeqN: " + seqN);
					    
						long ackN = 0;
						ackN = (long) packet.getUByte(42);
						ackN =  (long) (ackN * Math.pow(16, 2)  + packet.getUByte(43));
						ackN =  (long) (ackN * Math.pow(16, 2)  + packet.getUByte(44));
						ackN =  (long) (ackN * Math.pow(16, 2)  + packet.getUByte(45));
						int tcpFlag;
						tcpFlag = (int) packet.getUByte(47);
						if(tcpFlag == 2){
							synSeen = true;
						}
						if(tcpFlag == 18){
							synAckSeen = true;
							if(synSeen)
								numTcp++;
						}
						
						if(tcpFlag==17){
							
							synSeen = false;
							synAckSeen = false; 
							
						}
				}
			}
		}, errbuf);
		FileInfo fileinfo = new FileInfo();
		fileinfo.numTcp = numTcp; numTcp = 0;
		fileinfo.numPackets = numPackets; numPackets = 0;
		fileinfo.rawBytes = rawBytes; rawBytes = 0;
		fileinfo.timeTaken = fileTime.get(fileTime.size()-1) - fileTime.get(0);
		fileTime.clear();
		fileInfoList.add(fileinfo);
	}
}

