package edu.wisc.cs.project.secure;

import java.util.ArrayList;
import java.util.HashSet;

import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionType;

public class Alias {

	// source alias set
	// destination alias set
	// action
	
	private OFMatch source = new OFMatch();
	private OFMatch destination = new OFMatch();
	
	// not sure if this is enough, will have to get a bit further to tell
	private ArrayList<OFAction> actions = null; 
	
	public Alias(OFFlowMod rule){
		// need to check for failures adding to the set
		actions = new ArrayList<OFAction>(rule.getActions());
		separateSourceAndDestination(rule);
	}
	/**
	 * Function to rip out all the source and destination information from the 
	 * original OFMatch and put them in separate OFMatch objects
	 */
	
	private void separateSourceAndDestination(OFFlowMod rule){
		OFMatch orig = rule.getMatch();
		// pull out all source fields in orig OFMatch
		
		
		// pull out all destination fields in orig OFMatch
		
		addRemapActions(rule);
	}
	
	/**
	 * Function to go through the actions and if there are remaps, then
	 * those need to be added to the source or destination sets (depending
	 * on the remap)
	 * @return
	 */
	
	private void addRemapActions(OFFlowMod rule){
		
	}
	
	/* --------- GETTERS --------- */
	
	public OFMatch getSource(){
		return this.source;
	}
	
	public OFMatch getDestination(){
		return this.destination;
	}
	
	public ArrayList<OFAction> getActions(){
		return this.actions;
	}
}
