
import java.util.HashMap;
import java.util.*;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Http;


public class httpPrint {
    int  count = 0;
     boolean synSeen;
	 boolean synAckSeen;
	 boolean finSeen;
	 long srcPortFinal;
	 long dstPortFinal;
	 
	 int numFlow;
	public static void main(String[] args) {
		httpPrint obj = new httpPrint();
		obj.doWork("http_8092.pcap");
	}

	public void doWork(String fi) {

		String FILENAME = fi;
		StringBuilder errbuf = new StringBuilder();
		Pcap pcap = Pcap.openOffline(FILENAME, errbuf);
		if (pcap == null) {
			System.err.println(errbuf);
			return;
		}
        Map<Long,SingleFlow> flowMap = new HashMap<Long, SingleFlow>();
		
		pcap.loop(-1, new JPacketHandler<StringBuilder>() {
              
			public void nextPacket(JPacket packet, StringBuilder errbuf) {
				
				if (packet.hasHeader(Tcp.ID)) {
					
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
						srcPortFinal = srcPort;
						
					}
					if(tcpFlag == 18){
						synAckSeen = true;
						dstPortFinal = srcPort;
					}
					
					if((tcpFlag == 24 || tcpFlag ==25) && synSeen && synAckSeen ){
						if (packet.hasHeader(Http.ID))
						{
							
						        for(int i = 54; i<154;i++){
								System.out.print(packet.getUTF8Char(i));
							
							
							
						    }
						}
						System.out.println("Source Port "+srcPort+"   Destination Port "+dstPort+", Sequence Number "+seqN+",  Ack Number "+ackN );
						
					   
					}
					
					if(tcpFlag ==17){
						numFlow++;
						synAckSeen = false;
						synSeen = false;
						System.out.println("**********************************");
					}
				}
			}
		}, errbuf);
			
				
		
		System.out.println("The End "+ numFlow);
	}
}
