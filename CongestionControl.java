/* Prints the first 5 Congestion window in a Wireshark trace. Also, it calculates the number of time 
   re-transmission occurred due to Timeout and due to 3-ACK duplicate

Author : Arun Rajan
Stony Brook University
*/


import java.util.HashMap;
import java.util.*;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.protocol.tcpip.Tcp;

class  SingleFlowCongestion extends SingleFlow{
	long sSthresh;
	long mss;
	List<Long> cWList;
	
}
public class CongestionControl {
    int  count = 0;
	public static void main(String[] args) {
		CongestionControl obj = new CongestionControl();
		
		
		System.out.println("This Program does 2 things: ");
		System.out.println("1. Print the first five congestion windows");
		System.out.println("2. Compute the number of times retransmission occurred due to Timeout and 3 Ack");
	    
		System.out.println("from rfc2581 : IW = min (4*SMSS, max (2*SMSS, 4380 bytes))");
		
		System.out.println("We know that ssthresh is equal to receive window size that comes in the SYN - ACK packets");
		System.out.println("Initial window size is calculated by the above formula: it grows as follows:);"
				+ "With every Ack the window size grows by 1 till it hit the ssthresh value. It is called Slow start phase");
		System.out.println("Once we reach ssthresh, the window size grow by 1 only when all the packet in that"
				+ "window gets acknowledged. It is called congestion avoidance");
				
		
		System.out.println();

		
		System.out.println("To calculate the retransmission by 3 Ack, we use a map and store Sequence Number and an integer as key value pair");
		System.out.println("Once we get ack for a packet again, it means some packet sent after this packet got lost and );"
				+ "receiver is sending the ack for previous packet");
		System.out.println("Finally, after each flow finishes, we calculate the entries in the map that has "
				+ "value larger than 2, those are 3 Acks");
		
		System.out.println("***********************");
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
        Map<Long,SingleFlowCongestion> flowMap = new HashMap<Long, SingleFlowCongestion>();
		
		pcap.loop(-1, new JPacketHandler<StringBuilder>() {
              
			public void nextPacket(JPacket packet, StringBuilder errbuf) {

				if (packet.hasHeader(Tcp.ID)) {
					int tcpFlag;
					tcpFlag = (int) packet.getUByte(47);
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
						//System.out.println("AckN: " + ackN);
					    if(srcPort!=80){
					    	if(flowMap.containsKey(srcPort)){
					    		SingleFlow flow = flowMap.get(srcPort);
						    	flow.timeStamps.add(packet.getCaptureHeader().timestampInMillis());
						    	if(tcpFlag==16){
							    	if(!flow.mp.containsKey(seqN)){
							    		  flow.mp.put(seqN, 0);	
							    	 }
							    	else{
							    		flow.lossCount++;
							    	}
						    	
						    	}
					    	}
					    	 else{   
					    		        SingleFlowCongestion flow = new SingleFlowCongestion();
								    	flow.mp = new HashMap<Long,Integer>();
								    	flow.timeStamps =  new ArrayList<Long>();
								    	flow.rttMap = new HashMap<Long,Long>();
								    	flow.rttList = new ArrayList<Long>();
								    	flow.cWList = new ArrayList<Long>();
								    	flowMap.put(srcPort, flow);
					    	            
								    	if(tcpFlag==2){
								    		long mss =  0;
								    		mss = (long) packet.getUByte(56);
											mss =  (long) (mss * Math.pow(16, 2)+ packet.getUByte(57));
											
											flow.mss = mss;
											//from rfc2581
											//IW = min (4*SMSS, max (2*SMSS, 4380 bytes))
								    		
											flow.cWList.add(Math.min (4*mss, Math.max(2*mss, 4380 )));
											
								    	}
								    	
					    	     }		
					    	
					    }
					    else{
					    	SingleFlowCongestion flow = flowMap.get(dstPort);
					    		if(flow!=null){
					    			flow.timeStamps.add(packet.getCaptureHeader().timestampInMillis());
					    			if(flow.mp.containsKey(ackN)){
					    				int temp = flow.mp.get(ackN);
					    				long cW = flow.cWList.get(flow.cWList.size()-1);
					    				flow.cWList.add(cW + flow.mss);
					    				flow.mp.put(ackN, temp+1);
					    			}	
					    		}
					    		
					     }//port 80 ends here
					
				  }
				} // if tcp packet ends here
			
		}, errbuf);
		
		for(Map.Entry<Long, SingleFlowCongestion> entry : flowMap.entrySet()){
			System.out.println("Source Port:  "+entry.getKey());
			SingleFlowCongestion flow = entry.getValue();
	       
	        int count3Ack = 0;
	        for(Map.Entry<Long, Integer> e : flow.mp.entrySet()){
	            if(e.getValue()>2)
	            	count3Ack++;
	        }
	        System.out.println("TimeOut Count " + (flow.lossCount - count3Ack ));
	        System.out.println("3Ack Count " + count3Ack);
	        
	        System.out.println("First 5 congestion windows (In Bytes)(RFC 2581 was referred for Initital congestion window calculation");
	        for(int i=0;i<5;i++)
	        	System.out.println(flow.cWList.get(i));
	        
	        System.out.println("*******************************************");		
		}
	}
}
