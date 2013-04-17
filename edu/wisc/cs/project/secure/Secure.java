package edu.wisc.cs.project.secure;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Vector;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

import net.floodlightcontroller.core.OFSwitchBase;

import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFFlowRemoved;
import org.openflow.protocol.OFPacketOut;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionDataLayerDestination;
import org.openflow.protocol.action.OFActionDataLayerSource;
import org.openflow.protocol.action.OFActionEnqueue;
import org.openflow.protocol.action.OFActionNetworkLayerDestination;
import org.openflow.protocol.action.OFActionNetworkLayerSource;
import org.openflow.protocol.action.OFActionNetworkTypeOfService;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.protocol.action.OFActionTransportLayerDestination;
import org.openflow.protocol.action.OFActionTransportLayerSource;
import org.openflow.protocol.action.OFActionVendor;
import org.openflow.protocol.action.OFActionVirtualLanIdentifier;
import org.openflow.protocol.action.OFActionVirtualLanPriorityCodePoint;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Secure {
	
	protected static Logger logger = LoggerFactory.getLogger(Secure.class);
	
	private static Secure instance = null;
	private ConcurrentHashMap<Long, Vector<Alias>> aliasSet = new ConcurrentHashMap<Long, Vector<Alias>>();
	private int rulesInstalled = 0;
	private int packetRejected = 0;
	
	/**
	 * This function is used in OFSwitchBase to check rules in the
	 * write functions to make sure the switch should get the rule
	 * 
	 * @param cRule - the rule to be written to the switch
	 * @param sw - the switch that is trying to write the rule, this way
	 * 				a view of the switch's current rules can be constructed
	 * @return - true or false, if the rule is allowed to be written or not
	 */
	
	public static Secure getInstance(){
		if(instance == null){
			instance = new Secure();
		}
		return instance;
	}
	
	protected Secure(){
		
	}
	
	public boolean checkFlowRule(OFFlowMod cRule, long dpid, OFSwitchBase sw){		
		//Vector<Alias> aliases = Set(dpid); //aliasSet.get(dpid);
		Vector<Alias> aliases = aliasSet.get(dpid);
		
		// If there are no rules in the flow table, add this one
		if(aliases == null){
//			logger.debug("------NO RULES IN FLOW TABLE, ALLOW------");
			Vector<Alias> alias = new Vector<Alias>();
			alias.add(new Alias(cRule));
			//putAliasSet(dpid, alias);
			aliasSet.put(dpid, alias);
			return true;
		}
				
		Alias cAlias = new Alias(cRule);
		
		for(Alias fAlias : aliases){
			// pairwise comparison of current flow table rules
			// with the candidate rule
						
			// If the actions are them same then allow, move on to the next rule in the flow table
			if(checkActions(cAlias.getActions(), fAlias.getActions()) == false){
				// Actions weren't the same, so need to check the inside of the rule
				boolean sourceUnionEmpty = checkAliasSources(cAlias, fAlias);
				boolean destinationUnionEmpty = checkAliasDestinations(cAlias, fAlias);
				
				if(checkDataLayerType(cAlias, fAlias) && checkNetworkProtocol(cAlias, fAlias) &&
						!sourceUnionEmpty && !destinationUnionEmpty){				
					// there were no empty sets, so there is a conflict
					// Don't allow the rule to be written to the switch
					
					logger.debug("-------RULE REJECTED--------");
					logger.debug("Refused rule = " + cRule);
					return false;
				}
			}
		}
		
		// No flow table conflicts, allow rule to be written
		logger.debug("-----NO CONFLICTS, ALLOW RULE-------");
		
		aliases.add(cAlias);
		//putAliasSet(dpid, aliases);
		aliasSet.put(dpid, aliases);
		
		return true;
	}
	
	public boolean checkPacketOut(OFPacketOut po, long dpid){

	//	checkRuleHardTimeouts(dpid);
		
		//Vector<Alias> aliases = getAliasSet(dpid);
		Vector<Alias> aliases = aliasSet.get(dpid);
		if(aliases == null){
			// If there is nothing in the flow table, allow the packet to be written
			return true;
		}
			
		Alias cPO = new Alias(po);
		
		// make sure the po doesn't violate any of the current
		// rules in the flow table
		synchronized(aliases){
			for(Alias fAlias : aliases){
				if(checkActions(cPO.getActions(), fAlias.getActions()) == false){
					
					// If the actions are not the same need to check the packet
					boolean sourceUnionEmpty = checkAliasSources(cPO, fAlias);
					boolean destinationUnionEmpty = checkAliasDestinations(cPO, fAlias);
					
					if(po.getPacketData() == null && !sourceUnionEmpty && !destinationUnionEmpty){
						// TCP handshakes don't have and packet data, since packet data
						// is what floodlight uses to figure out the DL type and the NW Proto
						// then we can't consider them when deciding to refuse the packet for
						// a handshake.
		//				logger.debug("-------PACKET OUT REJECTED-------");
	//					logger.debug("Refused packet = " + po);
						packetRejected++;
						return false;
					}
					else if(checkDataLayerType(cPO, fAlias) && checkNetworkProtocol(cPO, fAlias) &&
							!sourceUnionEmpty && !destinationUnionEmpty){
	//					logger.debug("-------PACKET OUT REJECTED-------");
	//					logger.debug("Refused packet = " + po);
						packetRejected++;
						return false;
					}									
				}
			}
		}
		
//		logger.debug("------------NO CONFLICTS, ALLOW PACKET OUT-------");
		return true;
	}
	
	/**
	 * Function to access the HashMap of all the aliases. Effectively puts a lock around
	 * the alias HashMap.
	 * 
	 * @param dpid - switch data path identifier
	 * @param write - boolean saying if you want to write to the HashMap
	 * @param alias - alias to write to the hashmap
	 * @return - if write is false, then just read the HashSet from for the switch
	 */
	private synchronized Vector<Alias> accessAliasSet(long dpid, boolean write, Vector<Alias> alias){
		if(write){
			aliasSet.put(dpid, alias);
			return null;
		}
		else{
			return aliasSet.get(dpid);
		}
	}
	
	private synchronized Vector<Alias> getAliasSet(long dpid){
		return getSetCopy(accessAliasSet(dpid, false, null));
		//return accessAliasSet(dpid, false, null);
	}
	
	private Vector<Alias> getSetCopy(Vector<Alias> original){
		if(original == null){
			return null;
		}
		Vector<Alias> copy = new Vector<Alias>();
		for(Alias orig : original){
			copy.add(new Alias(orig));
		}
		return copy;
	}
	
	private synchronized void putAliasSet(long dpid, Vector<Alias> alias){
		accessAliasSet(dpid, true, alias);
	}
	
	public void removeFlowRule(OFFlowRemoved flowRemoved, long dpid){
//		logger.debug("Reason: " + flowRemoved.getReason());
		Alias remove = new Alias(flowRemoved.getMatch());
		
		//Vector<Alias> aliases = getAliasSet(dpid);
		Vector<Alias> aliases = aliasSet.get(dpid);
//		logger.debug("Alias set size: " + aliases.size());
		if(aliases != null){ // this shouldn't ever be null, we have a big issue if it is
			Alias toDelete = null;
			int count = 0;
			for(Alias alias : aliases){
				// Look for the flow rule in the set that corresponds to the removal
				// notification
				//logger.debug("Equality check: " + alias.equals(remove));
				if(alias.equals(remove)){
					toDelete = alias;
					count++;
				}
			}
			if(count > 1){
				logger.debug("\n\n\n FOUND MORE THAN ONE ALIAS TO REMOVE ON FLOW REMOVAL\n\n");
				return;
			}
			else if(count == 1){
				aliases.remove(toDelete);
				//putAliasSet(dpid, aliases);
				aliasSet.put(dpid, aliases);
			}
		}
//		logger.debug("Alias set size after: " + getAliasSet(dpid).size());
	}
	
	private boolean checkDataLayerType(Alias cAlias, Alias fAlias){
		// These could potentially not be set, but that's ok, since that
		// means they are both wildcarded
		if(cAlias.getDataLayerType() == fAlias.getDataLayerType()){
			return true;
		}
		else {
			return false;
		}
	}
	
	private boolean checkNetworkProtocol(Alias cAlias, Alias fAlias){
		// These could potentially not be set, but that's ok, since that
		// means they are both wildcarded
		if(cAlias.getNetworkProtocol() == fAlias.getNetworkProtocol()){
			return true;
		}
		else{
			return false;
		}
	}
		
	private int checkDataLayer(ArrayList<byte[]> cDL, ArrayList<byte[]> fDL){
		
		if(cDL.size() != 0 || fDL.size() != 0){
			// Then at least one of the them has their dl_src set, look for intersection
			
			if(cDL.size() == 0 || fDL.size() == 0){
				return 0;
			}
			
			// Neither are wildcarded so go through and find if there is intersection
			
			for(byte[] c : cDL){
				for(byte[] f : fDL){
					if(Arrays.equals(c, f)){
						return 0;
					}
				}
			}
		}			
		
		return 1;
	}
	
	private int checkNetworkLayer(ArrayList<Integer> cNW, ArrayList<Integer> fNW){
		
		if(cNW.size() != 0 || fNW.size() != 0){
			if(cNW.size() == 0 || fNW.size() == 0){
				return 0;
			}
			
			for(int c : cNW){
				for(int f : fNW){
					if(c == f){
						return 0;
					}
				}
			}
		}
		
		return 1;
	}
	
	private int checkTransport(ArrayList<Short> cTP, ArrayList<Short> fTP){
		
		if(cTP.size() != 0 || fTP.size() != 0){
			if(cTP.size() == 0 || fTP.size() == 0){
				return 0;
			}
			
			for(short c : cTP){
				for(short f : fTP){
					if(c == f){
						return 0;
					}
				}
			}
		}
		
		return 1;
	}
	
	private boolean checkAliasSources(Alias cAlias, Alias fAlias){
		int dlSrcEmpty = -1;
		int nwSrcEmpty = -1;
		int tpSrcEmpty = -1;
		
		if(!(cAlias.getDataLayerSource().size() == 0 && fAlias.getDataLayerSource().size() == 0)){
			dlSrcEmpty = checkDataLayer(cAlias.getDataLayerSource(), fAlias.getDataLayerSource());
		}
		if(!(cAlias.getNetworkSource().size() == 0 && fAlias.getNetworkSource().size() == 0)){
			nwSrcEmpty = checkNetworkLayer(cAlias.getNetworkSource(), fAlias.getNetworkSource());
		}
		if(!(cAlias.getTransportSource().size() == 0 && fAlias.getTransportSource().size() == 0)){
			tpSrcEmpty = checkTransport(cAlias.getTransportSource(), fAlias.getTransportSource());
		}
		
		if(dlSrcEmpty > -1 && nwSrcEmpty > -1 && tpSrcEmpty > -1){
			return (dlSrcEmpty + nwSrcEmpty + tpSrcEmpty) > 0;
		}
		else if(dlSrcEmpty > -1 && nwSrcEmpty > -1 && tpSrcEmpty == -1){
			return (dlSrcEmpty + nwSrcEmpty) > 0;
		}
		else if(dlSrcEmpty > -1 && nwSrcEmpty == -1 && tpSrcEmpty > -1){
			return (dlSrcEmpty + tpSrcEmpty) > 0;
		}
		else if(dlSrcEmpty > -1 && nwSrcEmpty == -1 && tpSrcEmpty == -1){
			return (dlSrcEmpty) > 0;
		}
		else if(dlSrcEmpty == -1 && nwSrcEmpty > -1 && tpSrcEmpty > -1){
			return (nwSrcEmpty + tpSrcEmpty) > 0;
		}
		else if(dlSrcEmpty == -1 && nwSrcEmpty > -1 && tpSrcEmpty == -1){
			return (nwSrcEmpty) > 0;
		}
		else if(dlSrcEmpty == -1 && nwSrcEmpty == -1 && tpSrcEmpty > -1){
			return (tpSrcEmpty) > 0;
		}
		else if(dlSrcEmpty == -1 && nwSrcEmpty == -1 && tpSrcEmpty == -1){
			return true;
		}
		return true;
	}
	
	
	
	private boolean checkAliasDestinations(Alias cAlias, Alias fAlias){
		int dlDstEmpty = -1;
		int nwDstEmpty = -1;
		int tpDstEmpty = -1;
		
		if(!(cAlias.getDataLayerDestination().size() == 0 && fAlias.getDataLayerDestination().size() == 0)){
			dlDstEmpty = checkDataLayer(cAlias.getDataLayerDestination(), fAlias.getDataLayerDestination());
		}
		if(!(cAlias.getNetworkDestination().size() == 0 && fAlias.getNetworkDestination().size() == 0)){
			nwDstEmpty = checkNetworkLayer(cAlias.getNetworkDestination(), fAlias.getNetworkDestination());
		}
		if(!(cAlias.getTransportDestination().size() == 0 && fAlias.getTransportDestination().size() == 0)){
			tpDstEmpty = checkTransport(cAlias.getTransportDestination(), fAlias.getTransportDestination());
		}
				
		if(dlDstEmpty > -1 && nwDstEmpty > -1 && tpDstEmpty > -1){
			return (dlDstEmpty + nwDstEmpty + tpDstEmpty) > 0;
		}
		else if(dlDstEmpty > -1 && nwDstEmpty > -1 && tpDstEmpty == -1){
			return (dlDstEmpty + nwDstEmpty) > 0;
		}
		else if(dlDstEmpty > -1 && nwDstEmpty == -1 && tpDstEmpty > -1){
			return (dlDstEmpty + tpDstEmpty) > 0;
		}
		else if(dlDstEmpty > -1 && nwDstEmpty == -1 && tpDstEmpty == -1){
			return (dlDstEmpty) > 0;
		}
		else if(dlDstEmpty == -1 && nwDstEmpty > -1 && tpDstEmpty > -1){
			return (nwDstEmpty + tpDstEmpty) > 0;
		}
		else if(dlDstEmpty == -1 && nwDstEmpty > -1 && tpDstEmpty == -1){
			return (nwDstEmpty) > 0;
		}
		else if(dlDstEmpty == -1 && nwDstEmpty == -1 && tpDstEmpty > -1){
			return (tpDstEmpty) > 0;
		}
		else if(dlDstEmpty == -1 && nwDstEmpty == -1 && tpDstEmpty == -1){
			return true;
		}
		return true;
	}
	
	/**
	 * Check to see if the lists of actions for the two rules are equal
	 * 
	 * @param cAction - list of candidate actions
	 * @param fActions - list of actions from rule already in the flow table
	 * @return true or false depending on if the lists are equal to each other
	 */
	
	private boolean checkActions(CopyOnWriteArrayList<OFAction> cActions, CopyOnWriteArrayList<OFAction> fActions){
		
		if(cActions == null && fActions == null){
			// both are null, so both are drops, allow
			return true;
		}
		else if(cActions == null || fActions == null){
			// since both aren't null and we got here, one must be
			// null and the other isn't. Therefore different actions
			return false;
		}
		
		// This needs to copied via a copy constructor or a overridden clone function
	//	CopyOnWriteArrayList<OFAction> currentFlowActions = fActions; //new ArrayList<OFAction>(fActions);
		
		// If they aren't the same size they can't be the same action as a whole
		if(cActions.size() != fActions.size()){
			return false;
		}
		
		// check types and actions for each
		for(OFAction cAction : cActions){
			boolean foundSameType = false;
			for(int i = 0; i < fActions.size(); i++){
				if(cAction.getType() == fActions.get(i).getType()){
					foundSameType = true;
					// continue checking inside since they have the same type
					if(checkInnerAction(cAction, fActions.get(i))){
						// then the inner actions are the same
						// get rid of the action in the current rule set
						fActions.remove(i);
						break;
					}
					else {
						// the inner actions are not the same
						// therefore need to check the whole rule
						return false;
					}
				}
			}
			if(!foundSameType){
				// There were no fActions found that have the same
				// OFActionType as cAction, therefore these actions are
				// not the same, short-circuit the search
				return false;
			}
		}
	
		// Everything checks out to be the same
		return true;
	}
	
	/**
	 * Takes two actions and compares them to see if they are equal or not
	 * 
	 * @param cAction - candidate action
	 * @param fAction - action already in the flow table
	 * @return - true or false depending on if the actions are equal
	 */
	
	private boolean checkInnerAction(OFAction cAction, OFAction fAction){
		
		// Just a sanity check, these should be the same by the time they
		// get here
		if(cAction.getType() != fAction.getType()){
			return false;
		}
		
		switch(cAction.getType()){
			case OUTPUT:
				if(((OFActionOutput)cAction).getPort() == ((OFActionOutput)fAction).getPort()){
					return true;
				}
				else {
					return false;
				}
			case SET_VLAN_ID:
				if(((OFActionVirtualLanIdentifier)cAction).getVirtualLanIdentifier() == 
						((OFActionVirtualLanIdentifier)fAction).getVirtualLanIdentifier()){
					return true;
				}
				else {
					return false;
				}
			case SET_VLAN_PCP:
				if(((OFActionVirtualLanPriorityCodePoint)cAction).getVirtualLanPriorityCodePoint() == 
						((OFActionVirtualLanPriorityCodePoint)fAction).getVirtualLanPriorityCodePoint()) {
					return true;
				}
				else {
					return false;
				}
			case STRIP_VLAN:
				// TODO Not sure how to handle this action
				return true;
			case SET_DL_SRC:				
				if(Arrays.equals(((OFActionDataLayerSource)cAction).getDataLayerAddress(),
						((OFActionDataLayerSource)fAction).getDataLayerAddress())){
					return true;
				}
				else {
					return false;
				}
			case SET_DL_DST:		
				if(Arrays.equals(((OFActionDataLayerDestination)cAction).getDataLayerAddress(),
						((OFActionDataLayerDestination)fAction).getDataLayerAddress())){
					return true;
				}
				else {
					return false;
				}
			case SET_NW_SRC:
				if(((OFActionNetworkLayerSource)cAction).getNetworkAddress() == 
						((OFActionNetworkLayerSource)fAction).getNetworkAddress()){
					return true;
				}
				else {
					return false;
				}
			case SET_NW_DST:
				if(((OFActionNetworkLayerDestination)cAction).getNetworkAddress() == 
						((OFActionNetworkLayerDestination)fAction).getNetworkAddress()){
					return true;
				}
				else {
					return false;
				}
			case SET_NW_TOS:
				if(((OFActionNetworkTypeOfService)cAction).getNetworkTypeOfService() == 
						((OFActionNetworkTypeOfService)fAction).getNetworkTypeOfService()){
					return true;
				}
				else {
					return false;
				}
			case SET_TP_SRC:
				if(((OFActionTransportLayerSource)cAction).getTransportPort() == 
						((OFActionTransportLayerSource)fAction).getTransportPort()){
					return true;
				}
				else {
					return false;
				}
			case SET_TP_DST:
				if(((OFActionTransportLayerDestination)cAction).getTransportPort() == 
						((OFActionTransportLayerDestination)fAction).getTransportPort()){
					return true;
				}
				else {
					return false;
				}
			case OPAQUE_ENQUEUE:
				if(((OFActionEnqueue)cAction).getPort() == ((OFActionEnqueue)fAction).getPort() &&
						((OFActionEnqueue)cAction).getQueueId() == ((OFActionEnqueue)fAction).getQueueId()){
					return true;
				}
				else {
					return false;
				}
			case VENDOR:
				if(((OFActionVendor)cAction).getVendor() == ((OFActionVendor)fAction).getVendor()){
					return true;
				}
				else {
					return false;
				}
		}
		
		// This acts as a default
		// At the moment, if we don't know what it is, then allow it
		return true;
	}
	
	public void incrementRuleCount(){
		this.rulesInstalled++;
		logger.debug("Rule Count: " + this.rulesInstalled);
		logger.debug("Packets Rejected: " + this.packetRejected);
	}
}
