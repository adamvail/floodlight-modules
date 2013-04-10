package edu.wisc.cs.project.secure;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import net.floodlightcontroller.packet.Ethernet;

import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFPacketOut;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionDataLayerDestination;
import org.openflow.protocol.action.OFActionDataLayerSource;
import org.openflow.protocol.action.OFActionNetworkLayerDestination;
import org.openflow.protocol.action.OFActionNetworkLayerSource;
import org.openflow.protocol.action.OFActionNetworkTypeOfService;
import org.openflow.protocol.action.OFActionTransportLayerDestination;
import org.openflow.protocol.action.OFActionTransportLayerSource;
import org.openflow.protocol.action.OFActionType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Alias {
	
	protected static Logger logger = LoggerFactory.getLogger(Alias.class);

	// source alias set
	// destination alias set
	// action
	
	// Have arraylists for every field in the
	// OFMatch that. That we it'll be easier to
	// add actions to them and tell if they have
	// been wildcarded
	
	//private ArrayList<Short> inputPort = new ArrayList<Short>();
	private ArrayList<byte[]> dataLayerSource = new ArrayList<byte[]>();
	private ArrayList<byte[]> dataLayerDestination = new ArrayList<byte[]>();
	private ArrayList<Short> dataLayerVirtualLan = new ArrayList<Short>();
	private ArrayList<Byte> dataLayerVirtualLanPriorityCodePoint = new ArrayList<Byte>();
	//private ArrayList<Short> dataLayerType = new ArrayList<Short>();
	private ArrayList<Byte> networkTypeOfService = new ArrayList<Byte>();
	//private ArrayList<Byte> networkProtocol = new ArrayList<Byte>();
	private ArrayList<Integer> networkSource = new ArrayList<Integer>();
	private ArrayList<Integer> networkDestination = new ArrayList<Integer>();
	private ArrayList<Short> transportSource = new ArrayList<Short>();
	private ArrayList<Short> transportDestination = new ArrayList<Short>();
	
	private short inputPort = -1;
	private short dataLayerType = -1;
	private byte networkProtocol = -1;
	
	//private short idleTimeout = 0;
	private short hardTimeout = 0;
	private long startTime = 0;
	
	private ArrayList<OFAction> actions = null;
	
	public Alias(OFFlowMod rule){
		// need to check for failures adding to the set	
		if(rule.getActions() != null){
			this.actions = new ArrayList<OFAction>(rule.getActions());
		}
		logger.debug("Match: " + rule.getMatch());
		
		loadFromMatch(rule.getMatch());
		loadActions(rule.getActions());
		startTime = System.currentTimeMillis() / 1000;
		hardTimeout = rule.getHardTimeout();
	}
	
	/**
	 * This is used when deleting flows.
	 * The switch will send an OFFlowRemoved packet
	 * which has the match from the flow that was removed.
	 * 
	 * @param match - match of the removed flow
	 */
	public Alias(OFMatch match){
		loadFromMatch(match);
	}
	
	public Alias(OFPacketOut po){
		
		if(po.getActions() != null){
			this.actions = new ArrayList<OFAction>(po.getActions());
		}
				
		OFMatch match = new OFMatch();
		if(po.getPacketData() != null){
			match.loadFromPacket(po.getPacketData(), po.getInPort());
			loadFromMatch(match);
		}
		
		loadActions(po.getActions());
	}
	
	private void loadFromPacket(OFPacketOut po){
		this.inputPort = po.getInPort();
		
	}
	
	/**
	 * If the value for the different match fields are not their default values of 0,
	 * then add them to the List structure since they are in use
	 * @param match
	 */
	
	private void loadFromMatch(OFMatch match){
		byte[] zero = new byte[] { 0x0, 0x0, 0x0, 0x0, 0x0, 0x0 };
		if(match.getInputPort() != 0) this.inputPort = match.getInputPort();
		if(!Arrays.equals(match.getDataLayerSource(), zero)) this.dataLayerSource.add(match.getDataLayerSource());
		if(!Arrays.equals(match.getDataLayerDestination(), zero)) this.dataLayerDestination.add(match.getDataLayerDestination());
		if(match.getDataLayerVirtualLan() != Ethernet.VLAN_UNTAGGED) this.dataLayerVirtualLan.add(match.getDataLayerVirtualLan());
		if(match.getDataLayerVirtualLanPriorityCodePoint() != 0) this.dataLayerVirtualLanPriorityCodePoint.add(match.getDataLayerVirtualLanPriorityCodePoint());
		if(match.getDataLayerType() != 0) this.dataLayerType = match.getDataLayerType();
		if(match.getNetworkTypeOfService() != 0) this.networkTypeOfService.add(match.getNetworkTypeOfService());
		if(match.getNetworkProtocol() != 0) this.networkProtocol = match.getNetworkProtocol();
		if(match.getNetworkSource() != 0) this.networkSource.add(match.getNetworkSource());
		if(match.getNetworkDestination() != 0) this.networkDestination.add(match.getNetworkDestination());
		if(match.getTransportSource() != 0) this.transportSource.add(match.getTransportSource());
		if(match.getTransportDestination() != 0) this.transportDestination.add(match.getTransportDestination());
	}
	
	/**
	 * Populates the source and destination sets with the results of relevant actions.
	 * Doesn't take all actions into account, mainly since I don't know how they would
	 * change the source and destination "bins". This should cover the general cases though.
	 * 
	 * @param actions
	 */
	
	private void loadActions(List<OFAction> actions){
		if(actions == null){
			return;
		}
		for(OFAction action : actions){
			OFActionType type = action.getType();
			switch (type){
				case OUTPUT:
					break;
				case SET_VLAN_ID:
					break;
				case SET_VLAN_PCP:
					break;
				case STRIP_VLAN:
					break;
				case SET_DL_SRC:
					this.dataLayerSource.add(((OFActionDataLayerSource)action).getDataLayerAddress());
					break;
				case SET_DL_DST:
					this.dataLayerDestination.add(((OFActionDataLayerDestination)action).getDataLayerAddress());
					break;
				case SET_NW_SRC:
					this.networkSource.add(((OFActionNetworkLayerSource)action).getNetworkAddress());
					break;
				case SET_NW_DST:
					this.networkDestination.add(((OFActionNetworkLayerDestination)action).getNetworkAddress());
					break;
				case SET_NW_TOS:
					this.networkTypeOfService.add(((OFActionNetworkTypeOfService)action).getNetworkTypeOfService());
					break;
				case SET_TP_SRC:
					this.transportSource.add(((OFActionTransportLayerSource)action).getTransportPort());
					break;
				case SET_TP_DST:
					this.transportDestination.add(((OFActionTransportLayerDestination)action).getTransportPort());
					break;
				case OPAQUE_ENQUEUE:
					break;
				case VENDOR:
					break;
			}
		}
	}
		
	public ArrayList<OFAction> getActions(){
		return actions;
	}
	
	public short getInputPort(){
		return inputPort;
	}
	
	public ArrayList<byte[]> getDataLayerSource(){
		return dataLayerSource;
	}
	
	public ArrayList<byte[]> getDataLayerDestination(){
		return dataLayerDestination;
	}
	
	public short getDataLayerType(){
		return dataLayerType;
	}
	
	public ArrayList<Short> getDataLayerVirtualLan(){
		return dataLayerVirtualLan;
	}
	
	public ArrayList<Byte> getDataLayerVirtualLanPriorityCodePoint(){
		return dataLayerVirtualLanPriorityCodePoint;
	}
	
	public ArrayList<Integer> getNetworkSource(){
		return networkSource;
	}
	
	public ArrayList<Integer> getNetworkDestination(){
		return networkDestination;
	}
	
	public byte getNetworkProtocol(){
		return networkProtocol;
	}
	
	public ArrayList<Byte> getNetworkTypeOfService(){
		return networkTypeOfService;
	}
	
	public ArrayList<Short> getTransportSource(){
		return transportSource;
	}
	
	public ArrayList<Short> getTransportDestination(){
		return transportDestination;
	}
	
	public long getStartTime(){
		return startTime;
	}
	
	public short getHardTimeout(){
		return hardTimeout;
	}
	
	public boolean equals(Alias alias){
		
		// at the moment just check the main stuff
		
		if(alias.getInputPort() != this.inputPort){
			logger.debug("Input ports of aliases are different");
			return false;
		}
		else if(alias.getDataLayerType() != -1  && 
				alias.getDataLayerType() != this.dataLayerType){
			// DataLayer type is not the same
			logger.debug("DL Type of aliases are different");
			logger.debug("fAlias: " + this.dataLayerType);
			logger.debug("cAlias: " + alias.getDataLayerType());
			return false;
		}
		else if(alias.getNetworkProtocol() != -1 && alias.getNetworkProtocol() != this.networkProtocol){
			logger.debug("Network Protocol of aliases are different");
			logger.debug("fAlias: " + this.networkProtocol);
			logger.debug("cAlias: " + alias.getNetworkProtocol());
			return false;
		}
		else if(alias.getDataLayerDestination().size() > 0){
			boolean found = false;
			for(byte[] dst : this.dataLayerDestination){
				if(Arrays.equals(dst, alias.getDataLayerDestination().get(0))){
					found = true;
					break;
				}
			}
			if(!found){
				logger.debug("DL Destination of aliases are different");
				return false;
			}			
		}
		else if(alias.getDataLayerSource().size() > 0){
			boolean found = false;
			for(byte[] src : this.dataLayerSource){
				if(Arrays.equals(src, alias.getDataLayerSource().get(0))){
					found = true;
					break;
				}
			}
			if(!found){
				logger.debug("DL Source of aliases are different");
				return false;
			}
		}
		else if(alias.getNetworkSource().size() > 0){
			boolean found = false;
			for(int src : this.getNetworkSource()){
				if(src == alias.getNetworkSource().get(0)){
					found = true;
					break;
				}
			}
			if(!found){
				logger.debug("NW Source of aliases are different");
				return false;
			}
		}
		else if(alias.getNetworkDestination().size() > 0){
			boolean found = false;
			for(int dst : this.getNetworkDestination()){
				if(dst == alias.getNetworkDestination().get(0)){
					found = true;
					break;
				}
			}
			if(!found){
				logger.debug("NW Destination of aliases are different");
				return false;
			}			
		}
		else if(alias.getTransportSource().size() > 0){
			boolean found = false;
			for(short src : this.getTransportSource()){
				if(src == alias.getTransportSource().get(0)){
					found = true;
					break;
				}
			}
			if(!found){
				logger.debug("TP Source of aliases are different");
				return false;
			}			
		}
		else if(alias.getTransportDestination().size() > 0){
			boolean found = false;
			for(short dst : this.getTransportDestination()){
				if(dst == alias.getTransportDestination().get(0)){
					found = true;
					break;
				}
			}
			if(!found){
				logger.debug("TP Destination of aliases are different");
				return false;
			}
		}
		
		// passed all the checks
		return true;
	}
}
