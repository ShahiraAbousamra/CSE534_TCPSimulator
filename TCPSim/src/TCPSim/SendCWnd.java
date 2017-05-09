package TCPSim;

import java.util.HashMap;

public class SendCWnd {
	long lastFrameSent;
	long lastAckReceived;
	long currentCWndSize;
	//long currentScaledWndSize;
	long scale;
	long maxWndSize;
	int maxWndSizeConst = 500;
	//long maxScaledWndSize;
	long initialCWndSize; // in bytes
	long receiverCurrentWndSize = -1;
	int duplicateAckCount = 0;
	MyTCPPacket[] sentPackets;
	int sentPacketsArrMax = 0;
	int head, tail;
	HashMap ackPacketsDictionary = new HashMap();
	int slowStartThreshold = 0;
	CWndPhase currentPhase;
	float cwindIncreaseFraction = 0;

	public SendCWnd(long initialCWndSize, int slowStartThreshold){
		this.initialCWndSize = initialCWndSize;
		this.currentCWndSize = initialCWndSize;
		this.slowStartThreshold = slowStartThreshold;
		lastFrameSent = 0;
		lastAckReceived = 0;
//		sentPacketsArrMax = (int)(maxWndSize/1000);
//		sentPackets = new MyTCPPacket[sentPacketsArrMax];
//		head = 0;
//		tail = 0;
		updateCWndSize(CWndUpdateEventType.INITIALIZE);

	}
	
	public void setMaxWndSize(int maxWndSize){
		this.maxWndSize = maxWndSize; 
		sentPacketsArrMax = maxWndSize/TCPCoordinator.MSS; // the number of packets sents without an ack will probably never exceed maxWndSizeConst so we use this as a max value
		if(sentPacketsArrMax > maxWndSizeConst)
			sentPacketsArrMax = maxWndSizeConst;
		sentPackets = new MyTCPPacket[sentPacketsArrMax];
		head = 0;
		tail = 0;
	}

	public long updateCWndSize(long newCWndSize){
		currentCWndSize =  newCWndSize > maxWndSize/TCPCoordinator.MSS? maxWndSize/TCPCoordinator.MSS : newCWndSize ;
		return currentCWndSize ;
	}
	
	// check if there is space in window > packet size and receiver window has space > packet size
	public boolean canSend(int packetSize)
	{		
		if((lastFrameSent - lastAckReceived) < (currentCWndSize * TCPCoordinator.MSS)
				&& (currentCWndSize * TCPCoordinator.MSS) - (lastFrameSent - lastAckReceived) > packetSize 
				&& (receiverCurrentWndSize < 0 || receiverCurrentWndSize > packetSize)){
			return true;
		}
		return false;
	}
	
	public long getCurrentMSSInFlight()
	{		
		if(lastFrameSent - lastAckReceived < 0)
			return 0;
		return Math.round((lastFrameSent - lastAckReceived)/TCPCoordinator.MSS + 0.5);
	}

	public void updateLastFrameSent(MyTCPPacket packet){
//		long newValue = packet.seqNum + packet.headerLength + packet.payloadLength; /// remove the TCP header from ack calc
		long newValue = packet.seqNum + packet.payloadLength + (packet.payloadLength>0?0: 1);
		assert(newValue > lastFrameSent);
		lastFrameSent = newValue;
		// add sent packet to buffer (for use if resend especially with triple duplicate ack)
		packet.ackNum = lastFrameSent; // set the ack num to use when sliding the window based on ack received
		sentPackets[tail] = packet;
//		ackPacketsDictionary.put(lastFrameSent, tail);
		tail++;
		if(tail >= sentPacketsArrMax) // circular list
			tail = 0;
		
	}

	// returns the number of duplicate acks
	public int updateLastAckRec(MyTCPPacket packet){
		if(lastAckReceived > packet.ackNum) // it is an old ack so ignore
			return -1;
		if(packet.ackNum > lastFrameSent) // it is not a valid ack number so ignore
			return -1;
		// check if same ack (for triple duplicate ack)
		if(lastAckReceived == packet.ackNum)
			duplicateAckCount++;
		else{
			duplicateAckCount = 0;
			progressSentPacketsArr(packet.ackNum);
		}
		lastAckReceived = packet.ackNum;
		receiverCurrentWndSize = packet.windowSize;
		return duplicateAckCount;
	}

	public void progressSentPacketsArr(long ackNum){
		if(head < tail){
			for(int i=head; i<tail; i++){
				if(sentPackets[i].ackNum <= ackNum)
					head++;
				else
					break;
			}
		}
		else{
			boolean done = false;
			for(int i=head; i<sentPacketsArrMax; i++){
				if(sentPackets[i].ackNum <= ackNum)
					head++;
				else{
					done = true;
					break;
				}
			}
			if(head >= sentPacketsArrMax)
				head = 0;
			if(done)
				return;
			for(int i=0; i<tail; i++){
				if(sentPackets[i].ackNum <= ackNum)
					head++;
				else{
					done = true;
					break;
				}
			}
			
			
		}
	}
	
	MyTCPPacket getPacketForResend(){
		return sentPackets[head];
	}

	void resetDuplicateAckCount(){
		duplicateAckCount = 0;
	}
	
	void updateCWndSize(CWndUpdateEventType event){	// TCP Reno
		if(event == CWndUpdateEventType.INITIALIZE){
			currentPhase = CWndPhase.SLOW_START;
			return;
		}
		if(event == CWndUpdateEventType.ACK){
			if(currentPhase == CWndPhase.SLOW_START){ 	// inc cwnd by MSS  -  if reach slow start threshold, move to cong avoidance
//				updateCWndSize(currentCWndSize + TCPCoordinator.MSS);
				updateCWndSize(currentCWndSize + 1);
				if(currentCWndSize >= slowStartThreshold)
					currentPhase = CWndPhase.CONGESTION_AVOIDANCE;
			}
			else if(currentPhase == CWndPhase.CONGESTION_AVOIDANCE){ // inc cwnd by MSS * MSS/cwnd
				cwindIncreaseFraction += 1 / (float)currentCWndSize;
				if(cwindIncreaseFraction >= 1){
//					updateCWndSize(currentCWndSize + TCPCoordinator.MSS);
					updateCWndSize(currentCWndSize + 1);
					cwindIncreaseFraction = 0;
				}
			}
			return;
		}
		if(event == CWndUpdateEventType.TIMEOUT){
			if(currentPhase == CWndPhase.SLOW_START){	// set ssthreshold to half current cwnd, set cwnd = initial cwnd
				slowStartThreshold = (int)currentCWndSize/2;
				updateCWndSize(initialCWndSize);
				if(initialCWndSize >= slowStartThreshold)
					currentPhase = CWndPhase.CONGESTION_AVOIDANCE;
			}
			else if(currentPhase == CWndPhase.CONGESTION_AVOIDANCE){	// set ssthreshold to half current cwnd, set cwnd = initial cwnd, go to slow start 
				slowStartThreshold = (int)currentCWndSize/2;
				updateCWndSize(initialCWndSize);
				currentPhase = CWndPhase.SLOW_START;
				if(initialCWndSize >= slowStartThreshold)
					currentPhase = CWndPhase.CONGESTION_AVOIDANCE;
			}
			return;
		}
		if(event == CWndUpdateEventType.TRIPLE_DUPLICATE_ACK){
			if(currentPhase == CWndPhase.SLOW_START){	// set ssthreshold to half current cwnd, set cwnd = half cwnd, go to cong avoidance
				slowStartThreshold = (int)currentCWndSize/2;
				updateCWndSize(slowStartThreshold);
				currentPhase = CWndPhase.CONGESTION_AVOIDANCE;
			}
			else if(currentPhase == CWndPhase.CONGESTION_AVOIDANCE){	// set ssthreshold to half current cwnd, set cwnd = = half cwnd 
				slowStartThreshold = (int)currentCWndSize/2;
				updateCWndSize(slowStartThreshold);
			}
			return;
		}
	}
}

