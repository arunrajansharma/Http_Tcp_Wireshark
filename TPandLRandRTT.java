import java.util.HashMap;
import java.util.*;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.protocol.tcpip.Tcp;

class SingleFlow {
	int tSize;
	int lossCount;
	long packetSent;
	Map<Long, Integer> mp;
	List<Long> timeStamps;
	Map<Long,Long> rttMap;
	List<Long> rttList;
}
public class TPandLRandRTT {
    int  count = 0;
	public static void main(String[] args) {

		TPandLRandRTT obj = new TPandLRandRTT();
		System.out.println("This program will do 3 things :");
		
		
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
		/*
		 * Each flow as an instance of SingleFlow will be stored here in the flowMap
		 */
        Map<Long,SingleFlow> flowMap = new HashMap<Long, SingleFlow>();
		pcap.loop(-1, new JPacketHandler<StringBuilder>() {
			public void nextPacket(JPacket packet, StringBuilder errbuf) {
				if (packet.hasHeader(Tcp.ID)) {
					int tcpFlag;
					tcpFlag = (int) packet.getUByte(47);
					if(tcpFlag==16){
						
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
						    	flow.packetSent++;
						    	if(flow.mp.containsKey(seqN)){
						    		flow.lossCount++;
						    	 }
						    	else{
						    		flow.mp.put(seqN, 1);
						    		flow.tSize += packet.size();
						    		
						    	}
						    	// avg RTT process
						    	if(!flow.rttMap.containsKey(seqN)){
						    		Long sTime = packet.getCaptureHeader().timestampInMillis();
						    		flow.rttMap.put(seqN, sTime);
						    	}
					    	}
					    	 else{
							    	SingleFlow flow = new SingleFlow();
							    	flow.mp = new HashMap<Long,Integer>();
							    	flow.timeStamps =  new ArrayList<Long>();
							    	flow.rttMap = new HashMap<Long,Long>();
							    	flow.rttList = new ArrayList<Long>();
							    	flowMap.put(srcPort, flow);
							    	
							    }
					    }
					    else{
					    		SingleFlow flow = flowMap.get(dstPort);
					    		if(flow!=null){
					    			flow.timeStamps.add(packet.getCaptureHeader().timestampInMillis());
					    			
						        	if(flow.rttMap.containsKey(ackN)){
						    				Long eTime = packet.getCaptureHeader().timestampInMillis();
						    				Long sTime = flow.rttMap.get(ackN);
						    				flow.rttList.add(eTime - sTime);			
					    				}
					    		}
					     }
					}
				  }
				} // if tcp packet ends here
			
		}, errbuf);
		
		for(Map.Entry<Long, SingleFlow> entry : flowMap.entrySet()){
			System.out.println(entry.getKey());
			SingleFlow flow = entry.getValue();;
			System.out.println("lossCount   "+flow.lossCount);
			System.out.println("Total Packet Sent   "+flow.packetSent);
			//System.out.println(flow.timeStamps.get(flow.timeStamps.size()-1));
			//System.out.println(flow.timeStamps.get(0));
			
			System.out.println("Loss Rate : "+  (double)((double)flow.lossCount / flow.packetSent));
			
			double timeSpent = (double)(flow.timeStamps.get(flow.timeStamps.size()-1) - flow.timeStamps.get(0));
			System.out.println("ThroughPut "+(flow.tSize*8*1/1000)/timeSpent+" Mbps");
			
			System.out.println("AVG RTT CALCULATION");
			Long sum = 0L ;
			for(Long t : flow.rttList){
				sum =  sum + t;
			}
			
			System.out.println("AVG RTT : " +(double)(sum/flow.rttList.size() ) +"milliseconds" );
			
			
			
			System.out.println("*******************Flow ends here ***********************");
			
					
		}
		
		System.out.println("Tcp Flow count "+flowMap.size());
	}
}
