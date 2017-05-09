package TCPSim;

import java.util.Comparator;

public class ReceivedPacketIdentifier implements Comparator<ReceivedPacketIdentifier>, Comparable<ReceivedPacketIdentifier>{
	long sequenceNumber;
	int size;
	int payloadSize;
//	int endByteNumber;
	
	public ReceivedPacketIdentifier(long sequenceNumber, int size, int payloadSize){
		this.sequenceNumber = sequenceNumber;
		this.size = size;
		this.payloadSize = payloadSize;
//		this.endByteNumber = sequenceNumber + size - 1;
	}
	
    public int compare(ReceivedPacketIdentifier x, ReceivedPacketIdentifier y)
    {
        if (x.sequenceNumber < y.sequenceNumber)
        {
            return -1;
        }
        if (x.sequenceNumber> y.sequenceNumber)
        {
            return 1;
        }
        return 0;
    }

	@Override
	public int compareTo(ReceivedPacketIdentifier o) {
        if (this.sequenceNumber < o.sequenceNumber)
        {
            return -1;
        }
        if (this.sequenceNumber> o.sequenceNumber)
        {
            return 1;
        }
        return 0;
	}

}
