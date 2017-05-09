package TCPSim;

import java.util.ArrayList;
import java.util.PriorityQueue;
import java.util.Queue;

public class TCPEndPoint {
	
	boolean isClient = false;
	NodeType nodeType;
	String ip = "";
	String cssID = "";

	SendCWnd sendCWnd = null;
	ReceiveCWnd receiveCWnd = null;
	//int receiverCurrentWndSize;
	long port = 0;
//	long lastSeqNumSent = 0;
//	long lastAckNumSent = 0;
//	long lastSeqNumRec = 0;
//	long lastAckNumRec = 0;
	Queue<TCPEvent> queueEvents = new PriorityQueue<TCPEvent>();
	boolean hasSendEvent = false;
	TCPEvent sendEvent = null;
	double currentTime = 0;
	long RTO = 0;
	MyTCPPacket sampleAckPacket = null;
	
//	ArrayList<TCPEvent> timeoutEvents = new ArrayList<TCPEvent>(); 
	
	public TCPEndPoint(String ip, boolean isClient, String cssID){
		this.ip = ip;
		this.isClient = isClient;
		nodeType = isClient? NodeType.CLIENT : NodeType.SERVER;
		this.sendCWnd = new SendCWnd(TCPCoordinator.initialCongWindowSize, TCPCoordinator.slowStartThreshold);
		this.receiveCWnd = new ReceiveCWnd();
		this.cssID = cssID;
		TCPCoordinator.logCWndPerRTT(isClient, sendCWnd.currentCWndSize, this.ip, 0);
	}

	public TCPEvent ProcessEvent(TCPEvent event){
		MyTCPPacket packet = event.packet;
		
		if(event.eventType == EventType.SEND){
			//MyTCPPacket packet = TCPCoordinator.flowsList.get(event.flowID).packets.get(event.packetIndx);
			if(!sendCWnd.canSend(packet.headerLength+packet.payloadLength)) // do nothing until an ack is received
			{
				hasSendEvent = true;
				sendEvent = event;
				return null;
			}
			
			// Progress time
			if(currentTime < event.eventTime)
				currentTime = event.eventTime;
			
			// update last send window
			sendCWnd.updateLastFrameSent(packet);

			long currentPacketsInFlight = sendCWnd.getCurrentMSSInFlight();
			TCPCoordinator.logEvent(event, currentTime, this.ip, "Destination = " + event.packet.destIP_str + ", \tSequence = " + event.packet.seqNum + ", \tPayload Length = " + event.packet.payloadLength + ", \t[CWnd = " +sendCWnd.currentCWndSize +", InFlight = " + currentPacketsInFlight +"]", cssID);
			TCPCoordinator.logPacketsInFlightPerRTT(isClient, currentPacketsInFlight, this.ip, currentTime);
			
			TCPCoordinator.tcpStatistics.totalPacketsSent++;
			TCPEvent replyEvent = null;
			if(!isLoss()){
				// Create event for the other end to receive
				replyEvent = new TCPEvent(EventType.RECEIVE,
						packet,					 
						TCPCoordinator.CalculatePacketReceiveTime(currentTime, packet.totalPacketSize, nodeType, NodeType.ROUTER ),
						packet.destIP_str, 
						event.flowID,
						this.nodeType,
						NodeType.ROUTER,
						currentTime);
				replyEvent.packetIndx = event.packetIndx;
			}
			else{
				TCPCoordinator.logEvent(null, currentTime, this.ip, "<Packet Lost>", cssID);
				TCPCoordinator.tcpStatistics.lostPacketsCount++;
				TCPCoordinator.tcpStatistics.lostTotalCount++;
			}
			
			// Create timeout event 
			TCPEvent timeoutEvent = new TCPEvent(EventType.TIMEOUT,
					packet,					 
					TCPCoordinator.CalculatePacketRTOTime(currentTime, packet.totalPacketSize), 
					packet.srcIP_str, 
					event.flowID,
					this.nodeType,
					this.nodeType,
					0);
			this.queueEvents.add(timeoutEvent);
//			this.timeoutEvents.add(timeoutEvent);

			// check if next time I will send and if so create an event for self
			// update last sent packet index
			if(TCPCoordinator.currentFlowLastSentPacketIndx < event.packetIndx)
				TCPCoordinator.currentFlowLastSentPacketIndx = event.packetIndx;
			hasSendEvent = false;
			sendEvent = null;
			createMyNextSendEvent(event);
			
			// progress time with the transmission time
			currentTime += packet.totalPacketSize/TCPCoordinator.bandwidth; 
					
			return replyEvent;
				 
		}
		else if(event.eventType == EventType.RECEIVE){
			// Progress time
			if(currentTime < event.eventTime)
				currentTime = event.eventTime;

			// if cannot receive the packet then drop it 
			// check there is space in receive buffer
			if(!receiveCWnd.canReceivePacket((int)packet.seqNum, packet.headerLength+packet.payloadLength)){
				TCPCoordinator.logEvent(event, currentTime, this.ip, "<Drop Packet> Source = " + event.packet.srcIP_str + ", \tSequence = " + event.packet.seqNum + ", \tPayload Length = " + event.packet.payloadLength, cssID);
				return null;
			}
			TCPCoordinator.logEvent(event, currentTime, this.ip, "Source = " + event.packet.srcIP_str + ", \tSequence = " + event.packet.seqNum + ", \tPayload Length = " + event.packet.payloadLength, cssID);
			
			// update the receive buffer (mark received, slide and progress)
			receiveCWnd.updateReceivePacket((int)packet.seqNum, packet.headerLength+packet.payloadLength, packet.payloadLength);
			
			// Create ack rec event 
			MyTCPPacket ackPacket = getSampleAckPacket(event.flowID);
			ackPacket.ackNum = receiveCWnd.minAcceptablePacket;
			ackPacket.windowSize = receiveCWnd.availableWndSize;
			
			TCPEvent ackEvent = null;
			TCPCoordinator.tcpStatistics.totalPacketsSent++;
			if(!isLoss()){
//				int x;
//				if(packet.seqNum == 705740079)
//					x = 0;
				ackEvent = new TCPEvent(EventType.ACK,
						ackPacket,					 
	//					TCPCoordinator.CalculatePacketReceiveTime(currentTime, packet.headerLength+packet.payloadLength), 
						TCPCoordinator.CalculatePacketReceiveTime(currentTime, packet.totalPacketSize, nodeType, NodeType.ROUTER ), 
						packet.srcIP_str, 
						event.flowID,
						this.nodeType,
						NodeType.ROUTER,
						event.sendingTime);
			}
			else{
				TCPCoordinator.logEvent(null, currentTime, this.ip, "<Ack Lost>", cssID);				
				TCPCoordinator.tcpStatistics.lostAcksCount++;
				TCPCoordinator.tcpStatistics.lostTotalCount++;
			}
			// check if next time I will send and if so create an event for self
//			hasSendEvent = false;
//			sendEvent = null;
			createMyNextSendEvent(event);

			// progress time with the transmission time
			currentTime += packet.totalPacketSize/TCPCoordinator.bandwidth; 

			return ackEvent;
		}
		else if(event.eventType == EventType.TIMEOUT){

			if(event.packet.resendCount > 0){
				event.packet.resendCount--;
				return null;
			}
			// Progress time
			if(currentTime < event.eventTime)
				currentTime = event.eventTime;
			
			// Check if timeout is still valid (i.e. ack not already received)
			// if an ack already received then ignore this timeout event
			if(event.packet.seqNum < sendCWnd.lastAckReceived)
				return null;
			
			TCPCoordinator.logEvent(event, currentTime, this.ip, "Destination = " + event.packet.destIP_str + ", \tSequence = " + event.packet.seqNum + ", \tPayload Length = " + event.packet.payloadLength, cssID);
			TCPCoordinator.tcpStatistics.timeoutCount++;
			TCPCoordinator.tcpStatistics.retransmissionsCount++;
			
			// reset triple duplicate ack
			sendCWnd.resetDuplicateAckCount();
			// Re-transmit
			MyTCPPacket resendPacket = event.packet;
			// Create event for the other end to receive 
			TCPCoordinator.tcpStatistics.totalPacketsSent++;
			TCPEvent replyEvent = new TCPEvent(EventType.RECEIVE,
					resendPacket,					 
					TCPCoordinator.CalculatePacketReceiveTime(currentTime, resendPacket.totalPacketSize, nodeType, NodeType.ROUTER ), 
					resendPacket.destIP_str, 
					event.flowID,
					this.nodeType,
					NodeType.ROUTER,
					currentTime);
				
			// Create timeout event 
			TCPEvent timeoutEvent = new TCPEvent(EventType.TIMEOUT,
					resendPacket,					 
					TCPCoordinator.CalculatePacketRTOTime(currentTime, resendPacket.totalPacketSize), 
					resendPacket.srcIP_str, 
					event.flowID,
					this.nodeType,
					this.nodeType,
					0);
			this.queueEvents.add(timeoutEvent);
//			this.timeoutEvents.add(timeoutEvent);
			this.sendCWnd.updateCWndSize(CWndUpdateEventType.TIMEOUT);
			TCPCoordinator.logCWndPerRTT(isClient, sendCWnd.currentCWndSize, this.ip, currentTime);
			
			// progress time with the transmission time
			currentTime += resendPacket.totalPacketSize/TCPCoordinator.bandwidth;
			return replyEvent;

		}
		else if(event.eventType == EventType.ACK){
			// Progress time
			if(currentTime < event.eventTime)
				currentTime = event.eventTime;

			// progress the window and update the receiver window size
			int duplicateAckCount = sendCWnd.updateLastAckRec(packet);
			if(duplicateAckCount < 0){// an old ack, so do nothing
				TCPCoordinator.logEvent(event, currentTime, this.ip, "<Old Ack Received> Source = " + event.packet.srcIP_str + ", \tAck = " + event.packet.ackNum, cssID);
				return null;
			}
				
			// Triple Duplicate Ack
			TCPEvent replyEvent = null;
//			duplicateAckCount = 3; ///////////XXXXXXXXXXXXXXXXX
			if(duplicateAckCount == 3){ 
				TCPCoordinator.logEvent(null, currentTime, this.ip, "<Triple Duplicate Ack> Source = " + event.packet.srcIP_str + ", \tAck = " + event.packet.ackNum, cssID);
				TCPCoordinator.tcpStatistics.tripleDupAckCount++;
				TCPCoordinator.tcpStatistics.retransmissionsCount++;
				long currentPacketsInFlight = sendCWnd.getCurrentMSSInFlight();
				TCPCoordinator.logEvent(event, currentTime, this.ip, "Source = " + event.packet.srcIP_str + ", \tAck = " + event.packet.ackNum + ", \t[CWnd = " +sendCWnd.currentCWndSize +", InFlight = " + currentPacketsInFlight +"]", cssID);
				TCPCoordinator.logPacketsInFlightPerRTT(isClient, currentPacketsInFlight, this.ip, currentTime);

				// Re-transmit
				MyTCPPacket resendPacket = sendCWnd.getPacketForResend();
				resendPacket.resendCount++;
				// reset the DuplicateAckCount
//				sendCWnd.resetDuplicateAckCount(); // do not reset so that further duplicate acks are not counted
				// Create event for the other end to receive 
				replyEvent = new TCPEvent(EventType.RECEIVE,
						resendPacket,					 
						TCPCoordinator.CalculatePacketReceiveTime(currentTime, resendPacket.totalPacketSize, nodeType, NodeType.ROUTER ), 
						resendPacket.destIP_str, 
						event.flowID,
						this.nodeType,
						NodeType.ROUTER,
						currentTime);
				
				// remove old timeout event
				// Create timeout event 
				TCPEvent timeoutEvent = new TCPEvent(EventType.TIMEOUT,
						resendPacket,					 
						TCPCoordinator.CalculatePacketRTOTime(currentTime, resendPacket.totalPacketSize), 
						resendPacket.srcIP_str, 
						event.flowID,
						this.nodeType,
						this.nodeType,
						0);
				this.queueEvents.add(timeoutEvent);
//				this.queueEvents.
//				this.timeoutEvents.add(timeoutEvent);
				this.sendCWnd.updateCWndSize(CWndUpdateEventType.TRIPLE_DUPLICATE_ACK);
				TCPCoordinator.logCWndPerRTT(isClient, sendCWnd.currentCWndSize, this.ip, currentTime);

				// progress time with the transmission time
				currentTime += resendPacket.totalPacketSize/TCPCoordinator.bandwidth; 
				
			}
			else{
				this.sendCWnd.updateCWndSize(CWndUpdateEventType.ACK);
				TCPCoordinator.logCWndPerRTT(isClient, sendCWnd.currentCWndSize, this.ip, currentTime);
//				this.sendCWnd.receiverCurrentWndSize = event.packet.windowSize; // update the receiver window size at the sender
				long currentPacketsInFlight = sendCWnd.getCurrentMSSInFlight();
				TCPCoordinator.logEvent(event, currentTime, this.ip, "Source = " + event.packet.srcIP_str + ", \tAck = " + event.packet.ackNum + ", \t[CWnd = " +sendCWnd.currentCWndSize +", InFlight = " + currentPacketsInFlight +"]", cssID);
				TCPCoordinator.logPacketsInFlightPerRTT(isClient, currentPacketsInFlight, this.ip, currentTime);

				createMyNextSendEvent(event);
			}
			if(duplicateAckCount == 0){
				double sampleRTT = currentTime - event.sendingTime;
				TCPCoordinator.rtt = 0.875 * TCPCoordinator.rtt + 0.125 * sampleRTT; 
				TCPCoordinator.tcpStatistics.totalSampleRTT += TCPCoordinator.rtt;
				TCPCoordinator.tcpStatistics.SampleRTTCount ++;
			}

			
			
			
			// check if next time I will send and if so create an event for self
//			hasSendEvent = false;
//			sendEvent = null;

			return replyEvent;
		}
//		else if(event.eventType == EventType.RTT){
//			TCPCoordinator.logCWndPerRTT(isClient, sendCWnd.currentCWndSize, this.ip);
////			if(isClient)
////				TCPCoordinator.tcpStatistics.cwndSizePerRTT_client.add(sendCWnd.currentCWndSize);
////			else
////				TCPCoordinator.tcpStatistics.cwndSizePerRTT_server.add(sendCWnd.currentCWndSize);
//			if(queueEvents.size() > 0)
//				queueEvents.add(new TCPEvent(EventType.RTT, currentTime + TCPCoordinator.rtt));
//			return null;
//		}
		
		return null;
	}
	
	public void createMyNextSendEvent(TCPEvent currentEvent){
		// if there is a previously not processed send event just use it
		if(hasSendEvent && sendEvent != null){	// means there is an upcoming send event pending 
			sendEvent.eventTime = currentTime;
			this.queueEvents.add(sendEvent);
			hasSendEvent = true; // means there is an upcoming send event either in queue (if sendEvent = null) or pending (if sendEvent not null)
			sendEvent = null; // means either has no upcoming send event (if hasSendEvent = false) or there is on in queue (if hasSendEvent = true)
			return;
		}
		else if(hasSendEvent)	// means there is an upcoming send event in queue already 
			return;
		// create event for sending following packet after transmission time
//		int nextPayloadIndx = TCPCoordinator.getNextPayloadIndx(currentEvent.flowID, currentEvent.packetIndx);
		int nextPayloadIndx = TCPCoordinator.getNextPayloadIndx(currentEvent.flowID, TCPCoordinator.currentFlowLastSentPacketIndx);
		if(nextPayloadIndx < 0){ // no more payload packets so return 
			return;
		}
		MyTCPPacket nextSendPacket = TCPCoordinator.flowsList.get(currentEvent.flowID-1).packets.get(nextPayloadIndx);
		// Only create the event if I am the sender
		if((isClient && !nextSendPacket.fromClient ) || (!isClient && nextSendPacket.fromClient )){
			hasSendEvent = false;
			sendEvent = null;
			return;
		}				
		// Create the event and add it to the queue of events 
		TCPEvent sendEvent = new TCPEvent(EventType.SEND,
				nextSendPacket,					 
				TCPCoordinator.CalculatePacketNextSendTime(currentTime, currentEvent.packet.totalPacketSize), 
				currentEvent.packet.srcIP_str, 
				currentEvent.flowID,
				this.nodeType,
				NodeType.ROUTER,
				0);
		sendEvent.packetIndx = nextPayloadIndx;
		this.queueEvents.add(sendEvent);
		sendEvent = null;
		hasSendEvent = true;
		
	}
	
	public MyTCPPacket getSampleAckPacket(int flowID){
		if(sampleAckPacket == null){
			ArrayList<MyTCPPacket> packets = TCPCoordinator.flowsList.get(flowID-1).packets;
			for(int i=0; i<packets.size(); i++){
				MyTCPPacket packet = packets.get(i);
				if(packet.payloadLength == 0 && packet.ACK && !packet.SYN && ((isClient && packet.fromClient) || (!isClient && !packet.fromClient))){
					sampleAckPacket = packet;
					break;
				}
			}
		}
		MyTCPPacket newAckPacket = new MyTCPPacket();
		newAckPacket.ACK=sampleAckPacket.ACK;  
		newAckPacket.SYN=sampleAckPacket.SYN;  
		newAckPacket.FIN=sampleAckPacket.FIN;  
		newAckPacket.ackNum=sampleAckPacket.ackNum;  
		newAckPacket.seqNum=sampleAckPacket.seqNum;  
		newAckPacket.destIP=sampleAckPacket.destIP;  
		newAckPacket.destIP_str=sampleAckPacket.destIP_str;  
		newAckPacket.destPort=sampleAckPacket.destPort;  
		newAckPacket.srcIP=sampleAckPacket.srcIP;  
		newAckPacket.srcIP_str=sampleAckPacket.srcIP_str;  
		newAckPacket.srcPort =sampleAckPacket.srcPort;  
		newAckPacket.flowID=sampleAckPacket.flowID;  
		newAckPacket.fromClient=sampleAckPacket.fromClient;  
		newAckPacket.headerLength=sampleAckPacket.headerLength;  
		newAckPacket.MSS=sampleAckPacket.MSS;  
		newAckPacket.payloadLength=sampleAckPacket.payloadLength;  
		newAckPacket.packetNumber=sampleAckPacket.packetNumber;  
		newAckPacket.resendCount=sampleAckPacket.resendCount;  
		newAckPacket.scaledWindowSize=sampleAckPacket.scaledWindowSize;  
		newAckPacket.windowSize=sampleAckPacket.windowSize;  
		newAckPacket.windowScale=sampleAckPacket.windowScale;
		newAckPacket.totalPacketSize =sampleAckPacket.totalPacketSize;
		return newAckPacket;
	}

	public boolean isLoss(){
		double loss = Math.random();
		if(loss < TCPCoordinator.lossRate)
			return true;
		return false;
	}
	
}
