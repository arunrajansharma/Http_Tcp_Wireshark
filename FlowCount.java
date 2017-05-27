/*
	This program counts the number of TCP flows in a Wireshark trace. 
	Also, for each such flow, it prints the sequence number (Seq), Ack number etc.
*/
import java.util.HashMap;
import java.util.*;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.protocol.tcpip.Tcp;

public class FlowCount {
    int  count = 0;
	public static void main(String[] args) {
		FlowCount obj = new FlowCount();
		
		System.out.println("This program will do two things :");
		System.out.println("1: Count the number of TCP flows ");
		System.out.println("2: For each such TCP flow, Print the value of Sequence number, Acknowledge number, Receive Window Size");
		System.out.println("***************************************");
		
		System.out.println("LOGIC :");
		System.out.println("To Count the number of flows, it is assumed that a TCP"
				+ " flow is there once we complete );"
				+ " the famous 3 way handshake between two systems( ports actually)"
				+ "Src --Dst : SYN"
				+ "Dst -- Src: SYN-ACK"
				+ "SRC-DST : ACK");
		
		System.out.println("*******************************************");
		
		System.out.println("After the 3 way handshake is completed, for each flow, first 2 transactions are printed");
		
		obj.doWork("assignment2.pcap");
	}

	public void doWork(String fi) {
		String FILENAME = fi;
		StringBuilder errbuf = new StringBuilder();
		Pcap pcap = Pcap.openOffline(FILENAME, errbuf);
		if (pcap == null) {
			System.err.println(errbuf);
			return;
		}
		
		Map<String,Integer> mp = new HashMap<String, Integer>();
		Map<String, Integer> mpFor2Trans = new HashMap<String,Integer>();
		
		
		
		pcap.loop(-1, new JPacketHandler<StringBuilder>() {
              
			public void nextPacket(JPacket packet, StringBuilder errbuf) {
				if (packet.hasHeader(Tcp.ID)) {
					int tcpFlag;
					tcpFlag = (int) packet.getUByte(47);
					
					if(tcpFlag ==2 || tcpFlag ==18 || tcpFlag==16){
						
						long srcPort = 0;
						srcPort = (long) packet.getUByte(34);
						srcPort =  (long) (srcPort * Math.pow(16, 2)  + packet.getUByte(35));
						//System.out.println("srcPort: " + srcPort);
					
						long dstPort = 0;
						dstPort = (long) packet.getUByte(36);
						dstPort =  (long) (dstPort * Math.pow(16, 2)  + packet.getUByte(37));
						//System.out.println("dstPort: " + dstPort);
						
						
						if(tcpFlag == 2){ // Syn flag
							String key = ""+srcPort+"#"+dstPort;
							if(!mp.containsKey(key)){
								mp.put(key, 1);
							}
						}
					    if(tcpFlag == 18){
					    	String key = ""+dstPort+"#"+srcPort;
					    	if(mp.containsKey(key)){
					    		mp.put(""+srcPort+"#"+dstPort, 1);
					    	}
					    }
					    
					    if(tcpFlag == 16){
					    	
					    	String key1 = ""+srcPort+"#"+dstPort;
					    	String key2 =  ""+dstPort+"#"+srcPort;
					    	String key3 = ""+srcPort+"#"+dstPort+"#seen";
					    	String key4 = ""+dstPort+"#"+srcPort+"#seen";
					    	
					    	
					    	if(mpFor2Trans.containsKey(key1)){
					    		int c = mpFor2Trans.get(key1);
					    		
					    		if(c < 2){
					    			System.out.println("Flow Between :"+srcPort+" "+dstPort);
					    			long seqN = 0;
									seqN = (long) packet.getUByte(38);
									seqN =  (long) (seqN * Math.pow(16, 2)  + packet.getUByte(39));
									seqN =  (long) (seqN * Math.pow(16, 2)  + packet.getUByte(40));
									seqN =  (long) (seqN * Math.pow(16, 2)  + packet.getUByte(41));
									System.out.println("SeqN: " + seqN);
									
									long ackN = 0;
									ackN = (long) packet.getUByte(42);
									ackN =  (long) (ackN * Math.pow(16, 2)  + packet.getUByte(43));
									ackN =  (long) (ackN * Math.pow(16, 2)  + packet.getUByte(44));
									ackN =  (long) (ackN * Math.pow(16, 2)  + packet.getUByte(45));
									System.out.println("AckN: " + ackN);
									
									long rws = 0;
									rws = (long) packet.getUByte(48);
									rws =  (long) (rws * Math.pow(16, 2)  + packet.getUByte(49));
									System.out.println("Receive Window Size: " + rws);
									
									System.out.println();
									mpFor2Trans.put(key1, c+1);
									
					    		}
					    	}
					    	
					    	
					    	if(mp.containsKey(key1) && mp.containsKey(key2) && !mp.containsKey(key3) && !mp.containsKey(key4)){
					    		count++;
					    		mp.put(key3,1);
					    		mp.put(key4,1);
					    		
					    		mpFor2Trans.put(key1,0);
					    		mpFor2Trans.put(key2, 0);
					    	}
					    	
					    	
					    }
					    
					} // flags if ends here
				} // if tcp packet ends here
			}

		}, errbuf);
		System.out.println("*************************************************");
		System.out.println("Tcp Flow count "+count);
	}
}
