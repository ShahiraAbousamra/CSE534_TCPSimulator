package TCPSim;

import java.util.ArrayList;
import java.util.PriorityQueue;
import java.util.Queue;

public class TCPRouter {
	
	boolean isRouter = true;
	NodeType nodeType;
	String ip = "";
	String cssID = "";

	long port = 0;
	
	Queue<TCPEvent> packetsReceivedBuffer = new PriorityQueue<TCPEvent>();
	Queue<TCPEvent> queueEvents = new PriorityQueue<TCPEvent>();
	int maxBufferSizeInBytes = 100;
	int remainingBufferSizeInBytes = 100;
	double switchingDelay = 0; 
	
	boolean hasSendEvent = false;
	double currentTime = 0;
	
//	ArrayList<TCPEvent> timeoutEvents = new ArrayList<TCPEvent>(); 
	
	public TCPRouter(String ip, int maxBufferSize, double switchingDelay, String cssID){
		this.ip = ip;
		this.isRouter = true;
		nodeType = NodeType.ROUTER;
		this.maxBufferSizeInBytes = maxBufferSize * TCPCoordinator.MSS;
		remainingBufferSizeInBytes = this.maxBufferSizeInBytes ; 
		this.switchingDelay = switchingDelay;
		this.cssID = cssID;
	}

	public TCPEvent ProcessEvent(TCPEvent event){
		MyTCPPacket packet = event.packet;
		
		if(event.eventType == EventType.FORWARD || event.eventType == EventType.FORWARD_ACK ){
			
			// Update the remainingBufferSize
			remainingBufferSizeInBytes += event.packet.headerLength + event.packet.payloadLength; 

			if(event.eventType == EventType.FORWARD) 
				TCPCoordinator.logEvent(event, currentTime, "Router", "Destination = " + event.packet.destIP_str + ", \tSequence = " + event.packet.seqNum + ", \tPayload Length = " + event.packet.payloadLength , cssID);
			else
				TCPCoordinator.logEvent(event, currentTime, "Router", "Destination = " + event.packet.destIP_str + ", \tAck = " + event.packet.ackNum , cssID);
			// Progress time
			if(currentTime < event.eventTime)
				currentTime = event.eventTime;
			// progress time with the switching delay
			currentTime += switchingDelay;
			
			
			TCPEvent replyEvent = null;
			// Create event for the other end to receive
			NodeType toNodeType = event.fromNodeType==NodeType.CLIENT?NodeType.SERVER:NodeType.CLIENT;
			replyEvent = new TCPEvent(event.eventType == EventType.FORWARD?EventType.RECEIVE:EventType.ACK,
					packet,					 
					TCPCoordinator.CalculatePacketReceiveTime(currentTime, packet.totalPacketSize, NodeType.ROUTER, toNodeType),
					packet.destIP_str, 
					event.flowID,
					this.nodeType,
					toNodeType,
					event.sendingTime);
			replyEvent.packetIndx = event.packetIndx;
			
			// progress time with the transmission time
			currentTime += packet.totalPacketSize/TCPCoordinator.bandwidth; 

			// If there are still packets in queue, add a send event
			hasSendEvent = false;
			createMyNextSendEvent(event);
			
					
			return replyEvent;
				 
		}
		else if(event.eventType == EventType.RECEIVE || event.eventType == EventType.ACK){
			// Progress time
			if(currentTime < event.eventTime)
				currentTime = event.eventTime;

			// if cannot receive the packet then drop it 
			// check there is space in receive buffer
			if(remainingBufferSizeInBytes < event.packet.headerLength + event.packet.payloadLength){
				if(event.eventType == EventType.RECEIVE){ 
					TCPCoordinator.logEvent(event, currentTime, "Router" , "<Drop Packet - Buffer Full> Source = " + event.packet.srcIP_str + ", \tSequence = " + event.packet.seqNum + ", \tPayload Length = " + event.packet.payloadLength, cssID);
					TCPCoordinator.tcpStatistics.lostPacketsCount++;
					TCPCoordinator.tcpStatistics.lostTotalCount++;
				}
				else{
					TCPCoordinator.logEvent(event, currentTime, "Router" , "<Drop Ack - Buffer Full> Source = " + event.packet.srcIP_str + ", \tAck= " + event.packet.ackNum , cssID);
					TCPCoordinator.tcpStatistics.lostAcksCount++;
					TCPCoordinator.tcpStatistics.lostTotalCount++;
				}
				return null;
			}
			if(event.eventType == EventType.RECEIVE) 
				TCPCoordinator.logEvent(event, currentTime, "Router ", "Source = " + event.packet.srcIP_str + ", \tSequence = " + event.packet.seqNum + ", \tPayload Length = " + event.packet.payloadLength, cssID);
			else
				TCPCoordinator.logEvent(event, currentTime, "Router ", "Source = " + event.packet.srcIP_str + ", \tAck = " + event.packet.ackNum , cssID);
			
			// update the receive buffer (mark received, slide and progress)
			remainingBufferSizeInBytes -= event.packet.headerLength + event.packet.payloadLength;
			packetsReceivedBuffer.add(event);
			
			// check whether there is a send event for packets in buffer 
			createMyNextSendEvent(event);

//			// progress time with the transmission time ///////?????????????????
//			currentTime += packet.totalPacketSize/TCPCoordinator.bandwidth; 

			return null;
		}

		
		return null;
	}
	
	public void createMyNextSendEvent(TCPEvent currentEvent){
		if(hasSendEvent)	// means there is an upcoming send event in queue already 
			return;
		TCPEvent nextSendEvent = packetsReceivedBuffer.peek();			
		if(nextSendEvent != null){			
			nextSendEvent.eventType = nextSendEvent.eventType==EventType.RECEIVE? EventType.FORWARD:EventType.FORWARD_ACK;
//			nextSendEvent.eventTime = currentTime + TCPCoordinator.CalculatePacketNextSendTime(currentTime, currentEvent.packet.totalPacketSize);
			nextSendEvent.eventTime = currentTime ;
			this.queueEvents.add(nextSendEvent);
			hasSendEvent = true;
			// Remove the event from the receive buffer
			packetsReceivedBuffer.poll();
		}
		
	}
	

	public boolean isLoss(){
		double loss = Math.random();
		if(loss < TCPCoordinator.lossRate)
			return true;
		return false;
	}
	
}
