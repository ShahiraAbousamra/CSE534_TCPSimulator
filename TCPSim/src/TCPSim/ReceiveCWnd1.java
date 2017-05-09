package TCPSim;


public class ReceiveCWnd1 {
//	long lastReceivedPacket;
//	long lastInOrderPacket;
	int minRecPacket;
	int maxAcceptablePacket;
	int minAcceptablePacket;
	long availableWndSize;
	//long currentScaledWndSize;
	long scale;
	int maxWndSize;
	//long maxScaledWndSize;
	boolean[] receiveBuffer;
	int head;

	public ReceiveCWnd1(){
		minRecPacket = Integer.MAX_VALUE;
	}
	public void setMaxReceiveBufferSize(int maxWndSize){
		this.maxWndSize = maxWndSize;
		availableWndSize = maxWndSize;
		receiveBuffer = new boolean[(int) maxWndSize];
		head = 0;
	}

	public boolean canReceivePacket(int seqNum, int packetSize){
		// Check within range
		if(seqNum < minAcceptablePacket)
			return false;
		if(seqNum+packetSize-1 > maxAcceptablePacket)
			return false;
		// Check not recevied before
		if(receiveBuffer[head + (seqNum - minAcceptablePacket)])
			return false;
		return true;
	}
	public void updateReceivePacket(int seqNum, int packetSize){
		int segmentStart = getCircularIndx(seqNum);
		int segmentEnd = getCircularIndx(seqNum + packetSize);
		if(segmentEnd <segmentStart){
			for(int i=segmentStart; i<maxWndSize; i++){
				receiveBuffer[i] = true;
			}
			for(int i=0; i<segmentEnd; i++){
				receiveBuffer[i] = true;
			}
		}
		else{
			for(int i=segmentStart; i<segmentEnd; i++){
				receiveBuffer[i] = true;
			}
		}
		
		availableWndSize -= packetSize;
		
		if(seqNum < minRecPacket){
			minRecPacket = seqNum;
		}
		// send packets to app and release some buffer
		if(seqNum == minAcceptablePacket){
			boolean done = false;
			int count = 0; 
			int tail = head == 0? maxWndSize-1:head-1;
			if(head < tail){
				for(int i=head; i<=tail; i++){
					if(receiveBuffer[i]){
						receiveBuffer[i] = false;
						count++;
					}
					else{ 
						done = true;
						break;
					}
				}
				
			}
			else{
				for(int i=head; i<maxWndSize; i++){
					if(receiveBuffer[i]){
						receiveBuffer[i] = false;
						count++;
					}
					else{
						done = true;
						break;
					}
					
				}
				if(!done){
					for(int i=0; i<=tail-1; i++){
						if(receiveBuffer[i]){
							receiveBuffer[i] = false;
							count++;
						}
						else{ 
							done = true;
							break;
						}				
					}
				}
			}
			progressWindow(count);
		}
	}
	
	public int getCircularIndx(int seqNum){
		int indx = head + (seqNum - minAcceptablePacket);
		if(indx > maxWndSize)
			indx = indx - maxWndSize;
		return indx;
	}

	public int progressWindow(int count){
		int indx = head + count;
		if(indx > maxWndSize)
			indx = indx - maxWndSize;
		head = indx;
		availableWndSize += count;
		minAcceptablePacket += count;
		maxAcceptablePacket += count;
		return indx;
	}
}
