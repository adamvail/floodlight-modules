package edu.wisc.cs.project.secure;

import java.util.HashSet;

import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.action.OFActionType;

public class Alias {

	// source alias set
	// destination alias set
	// action
	
	private HashSet<byte[]> source = new HashSet<byte[]>();
	private HashSet<byte[]> destination = new HashSet<byte[]>();
	
	// not sure if this is enough, will have to get a bit further to tell
	private HashSet<OFActionType> actions = new HashSet<OFActionType>(); 
	
	public Alias(OFFlowMod rule){
		// need to check for failures adding to the set
		this.source.add(rule.getMatch().getDataLayerSource());
	}
}
