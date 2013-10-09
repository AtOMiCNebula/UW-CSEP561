package edu.uw.cs.sdn.learningsw;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.openflow.protocol.OFFlowMod;
import org.openflow.protocol.OFMatch;
import org.openflow.protocol.OFMessage;
import org.openflow.protocol.OFPacketIn;
import org.openflow.protocol.OFPacketOut;
import org.openflow.protocol.OFPort;
import org.openflow.protocol.OFType;
import org.openflow.protocol.action.OFAction;
import org.openflow.protocol.action.OFActionOutput;
import org.openflow.util.U16;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.packet.Ethernet;

/*	
 * since we are listening to OpenFlow messages we need to 
 * register with the FloodlightProvider (IFloodlightProviderService class
 */
public class LearningSwitch implements IOFMessageListener, IFloodlightModule {

	/*
	 * member variables used in LearningSwitch
	 */
	protected IFloodlightProviderService floodlightProvider;
	protected Map<Long, Short> macToPort;
	protected static Logger logger;

	// 0 - nothing, 1 - HUB, 2 - LEARNING_SWITCH_WO_RULES, 3 - LEARNING_SWITCH_WITH_RULES
	protected static int CTRL_LEVEL = 0;
	protected static short FLOWMOD_DEFAULT_IDLE_TIMEOUT = 20; // in seconds
	protected static short FLOWMOD_DEFAULT_HARD_TIMEOUT = 0; // infinite

	/*
	 * important to override put an ID for our OFMessage listener
	 */
	@Override
	public String getName() {
		return LearningSwitch.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	/*
	 * important to override need to wire up to the module loading system by
	 * telling the module loader we depend on it
	 */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> fsrv = new ArrayList<Class<? extends IFloodlightService>>();
		fsrv.add(IFloodlightProviderService.class);
		return fsrv;
	}

	/*
	 * important to override load dependencies and initialize datastructures
	 */
	@Override
	public void init(FloodlightModuleContext context)
			throws FloodlightModuleException {
		floodlightProvider = context
				.getServiceImpl(IFloodlightProviderService.class);
		macToPort = new HashMap<Long, Short>();
		logger = LoggerFactory.getLogger(LearningSwitch.class);
	}

	/*
	 * important to override implement the basic listener - listen for PACKET_IN
	 * messages
	 */
	@Override
	public void startUp(FloodlightModuleContext context) {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
	}


	/*
	 * control logic which install static rules
	 */
	private Command ctrlLogicSwitchWithRules(IOFSwitch sw, OFPacketIn pi) {

		// TODO
		
		return Command.CONTINUE;
	}

	/*
	 * implement your own Learning Switch without rules 
	 */
	private Command ctrlLogicSwitchWithoutRules(IOFSwitch sw, OFPacketIn pi) {

		// TODO
		
		return Command.CONTINUE;
	}

	/*
	 * hub implementation
	 */
	private Command ctrlLogicHub(IOFSwitch sw, OFPacketIn pi) {

		OFPacketOut po = (OFPacketOut) floodlightProvider.getOFMessageFactory()
				.getMessage(OFType.PACKET_OUT);
		po.setBufferId(pi.getBufferId()).setInPort(pi.getInPort());

		// set actions
		OFActionOutput action = new OFActionOutput()
				.setPort((short) OFPort.OFPP_FLOOD.getValue());
		po.setActions(Collections.singletonList((OFAction) action));
		po.setActionsLength((short) OFActionOutput.MINIMUM_LENGTH);

		// set data if is is included in the packetin
		if (pi.getBufferId() == OFPacketOut.BUFFER_ID_NONE) {
			byte[] packetData = pi.getPacketData();
			po.setLength(U16.t(OFPacketOut.MINIMUM_LENGTH
					+ po.getActionsLength() + packetData.length));
			po.setPacketData(packetData);
		} else {
			po.setLength(U16.t(OFPacketOut.MINIMUM_LENGTH
					+ po.getActionsLength()));
		}
		try {
			sw.write(po, null);
		} catch (IOException e) {
			logger.error("Failure writing PacketOut", e);
		}

		return Command.CONTINUE;
	}

	/*
	 * this function handle the packets received from the switches
	 * place to implement your smart SDN application 
	 * */
	@Override
	public net.floodlightcontroller.core.IListener.Command receive(
			IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {

		OFMatch match = new OFMatch();
		match.loadFromPacket(((OFPacketIn) msg).getPacketData(),
				((OFPacketIn) msg).getInPort());

		if (match.getDataLayerType() != Ethernet.TYPE_IPv4)
			return Command.CONTINUE;

		switch (msg.getType()) {

		case PACKET_IN:
			logger.debug("Receive a packet !!!");

			// ACT LIKE A HUB
			if (LearningSwitch.CTRL_LEVEL == 1) {
				return this.ctrlLogicHub(sw, (OFPacketIn) msg);
			}
			
			// ACT LIKE A LEARNING SWITCH W/O RULES
			else if (LearningSwitch.CTRL_LEVEL == 2) {
				// TODO - implement your Learning Switch without rules here
				return this.ctrlLogicSwitchWithoutRules(sw, (OFPacketIn) msg);
			}
			
			// ACT LIKE A LEARNING SWITCH WITH RULES
			else if (LearningSwitch.CTRL_LEVEL == 3) {
				// TODO - implement Learning Switch with Rules
				return this.ctrlLogicSwitchWithRules(sw, (OFPacketIn) msg);
			}

		default:
			break;
		}
		return Command.CONTINUE;
	}

}
