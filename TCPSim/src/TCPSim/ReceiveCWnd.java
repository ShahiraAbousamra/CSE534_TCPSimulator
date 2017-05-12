/*
 * Author: Shahira Abousamra   
 * Under supervision of Prof. Aruna Balasubramanian  
 * CSE534: Fundamental of Computer Networks, Spring 2017 * 
 */

package TCPSim;

import java.util.PriorityQueue;
import java.util.Queue;

public class ReceiveCWnd {
//	long lastReceivedPacket;
//	long lastInOrderPacket;
//	int minRecPacket;
	long maxAcceptablePacket = -1;
	long minAcceptablePacket = -1;
	long availableWndSize;
	//long currentScaledWndSize;
	long scale;
	int maxWndSize = -1;
	//long maxScaledWndSize;
//	boolean[] receiveBuffer;
//	int head;
	Queue<ReceivedPacketIdentifier> queuePacketsReceived = new PriorityQueue<ReceivedPacketIdentifier>();

	public ReceiveCWnd(){
//		minRecPacket = Integer.MAX_VALUE;
	}
	public void setMaxReceiveBufferSize(int maxWndSize){
		this.maxWndSize = maxWndSize;
		availableWndSize = maxWndSize;
		if(minAcceptablePacket >= 0){
			maxAcceptablePacket =minAcceptablePacket +maxWndSize;  	
		}
//		receiveBuffer = new boolean[(int) maxWndSize];
//		head = 0;
	}

	public void setMinAcceptablePacket(long minAcceptableSequence){
		this.minAcceptablePacket = minAcceptableSequence;
		if(maxWndSize >= 0){
			maxAcceptablePacket =minAcceptablePacket +maxWndSize;  	
		}
//		receiveBuffer = new boolean[(int) maxWndSize];
//		head = 0;
	}

	public boolean canReceivePacket(long seqNum, int packetSize){
		// Check within range
		if(seqNum < minAcceptablePacket)
			return false;
		if(seqNum+packetSize-1 > maxAcceptablePacket)
			return false;
		// Check not recevied before
		if(queuePacketsReceived.contains(new ReceivedPacketIdentifier(seqNum, packetSize, 0)))
			return false;
//		if(receiveBuffer[head + (seqNum - minAcceptablePacket)])
//			return false;
		return true;
	}
	
	// adds packet received to queue 
	// update the availableWndSize 
	// and checks if some of the data can be sent to the application to release the buffer
	public void updateReceivePacket(int seqNum, int packetSize, int payloadSize){
		ReceivedPacketIdentifier packetIdentifier = new ReceivedPacketIdentifier(seqNum, packetSize, payloadSize);
//		if(queuePacketsReceived.contains(new ReceivedPacketIdentifier(seqNum, packetSize)))
//			return;
		queuePacketsReceived.add(packetIdentifier);
		availableWndSize -= packetSize;
//		if(seqNum < minRecPacket){
//			minRecPacket = seqNum;
//		}
		while(true){
			ReceivedPacketIdentifier packetIdentifier2 = queuePacketsReceived.peek();
			if(packetIdentifier2 == null)
				break;
			if(packetIdentifier2.sequenceNumber < minAcceptablePacket){
				queuePacketsReceived.poll();
				continue;
			}
			if(packetIdentifier2.sequenceNumber == minAcceptablePacket){
				queuePacketsReceived.poll();
//				minAcceptablePacket = packetIdentifier2.sequenceNumber + packetIdentifier2.size;
				minAcceptablePacket = packetIdentifier2.sequenceNumber + packetIdentifier2.payloadSize + (packetIdentifier2.payloadSize>0?0: 1); 
				availableWndSize += packetIdentifier2.size;
//				minAcceptablePacket += packetIdentifier2.size;
				maxAcceptablePacket += packetIdentifier2.size;
			}
			else
				break;
		}
		
//		int segmentStart = getCircularIndx(seqNum);
//		int segmentEnd = getCircularIndx(seqNum + packetSize);
//		if(segmentEnd <segmentStart){
//			for(int i=segmentStart; i<maxWndSize; i++){
//				receiveBuffer[i] = true;
//			}
//			for(int i=0; i<segmentEnd; i++){
//				receiveBuffer[i] = true;
//			}
//		}
//		else{
//			for(int i=segmentStart; i<segmentEnd; i++){
//				receiveBuffer[i] = true;
//			}
//		}
//		
//		availableWndSize -= packetSize;
//		
//		if(seqNum < minRecPacket){
//			minRecPacket = seqNum;
//		}
//		// send packets to app and release some buffer
//		if(seqNum == minAcceptablePacket){
//			boolean done = false;
//			int count = 0; 
//			int tail = head == 0? maxWndSize-1:head-1;
//			if(head < tail){
//				for(int i=head; i<=tail; i++){
//					if(receiveBuffer[i]){
//						receiveBuffer[i] = false;
//						count++;
//					}
//					else{ 
//						done = true;
//						break;
//					}
//				}
//				
//			}
//			else{
//				for(int i=head; i<maxWndSize; i++){
//					if(receiveBuffer[i]){
//						receiveBuffer[i] = false;
//						count++;
//					}
//					else{
//						done = true;
//						break;
//					}
//					
//				}
//				if(!done){
//					for(int i=0; i<=tail-1; i++){
//						if(receiveBuffer[i]){
//							receiveBuffer[i] = false;
//							count++;
//						}
//						else{ 
//							done = true;
//							break;
//						}				
//					}
//				}
//			}
//			progressWindow(count);
//		}
	}
	
//	public int getCircularIndx(int seqNum){
//		int indx = head + (seqNum - minAcceptablePacket);
//		if(indx > maxWndSize)
//			indx = indx - maxWndSize;
//		return indx;
//	}

//	public int progressWindow(int count){
//		int indx = head + count;
//		if(indx > maxWndSize)
//			indx = indx - maxWndSize;
//		head = indx;
//		availableWndSize += count;
//		minAcceptablePacket += count;
//		maxAcceptablePacket += count;
//		return indx;
//	}
}
