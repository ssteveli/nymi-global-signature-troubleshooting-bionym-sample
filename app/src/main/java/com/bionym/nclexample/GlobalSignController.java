package com.bionym.nclexample;

import android.content.Context;
import android.util.Log;

import com.bionym.ncl.Ncl;
import com.bionym.ncl.NclAdv;
import com.bionym.ncl.NclCallback;
import com.bionym.ncl.NclEvent;
import com.bionym.ncl.NclEventDetection;
import com.bionym.ncl.NclEventDisconnection;
import com.bionym.ncl.NclEventError;
import com.bionym.ncl.NclEventFind;
import com.bionym.ncl.NclEventGlobalVk;
import com.bionym.ncl.NclEventType;
import com.bionym.ncl.NclEventValidation;
import com.bionym.ncl.NclMessage;
import com.bionym.ncl.NclPartnerPrivateKey;
import com.bionym.ncl.NclPartnerPublicKey;
import com.bionym.ncl.NclProvision;
import com.bionym.ncl.NclSig;
import com.bionym.ncl.NclVk;
import com.bionym.ncl.NclVkId;

public class GlobalSignController {
	// Constants
	protected static final String LOG_TAG = "Nymi NCA GlobalSignController";
	protected static final int RSSI_THRESHOLD = -60; // the minimal RSSI for accepting a Nymi, this seems to be more reasonable for one sample due to fluctuation

    public final static byte[] staticPublicKey = { (byte) 0x71, (byte) 0x88, (byte) 0xee,
            (byte) 0xb, (byte) 0xf4, (byte) 0xd2, (byte) 0xe1, (byte) 0x74,
            (byte) 0xca, (byte) 0x5e, (byte) 0x29, (byte) 0x50, (byte) 0xe7,
            (byte) 0xaa, (byte) 0x24, (byte) 0x7d, (byte) 0x8a, (byte) 0xe8,
            (byte) 0xf0, (byte) 0x76, (byte) 0x95, (byte) 0x5, (byte) 0xea,
            (byte) 0x9d, (byte) 0xf1, (byte) 0xc6, (byte) 0xd1, (byte) 0xa6,
            (byte) 0x10, (byte) 0x55, (byte) 0xdb, (byte) 0x2, (byte) 0xed,
            (byte) 0x60, (byte) 0x1c, (byte) 0xa0, (byte) 0x7c, (byte) 0xa4,
            (byte) 0x9e, (byte) 0x52, (byte) 0xf8, (byte) 0x0, (byte) 0xa5,
            (byte) 0xec, (byte) 0xf9, (byte) 0xac, (byte) 0x54, (byte) 0xfa,
            (byte) 0xac, (byte) 0xff, (byte) 0x4f, (byte) 0x44, (byte) 0x19,
            (byte) 0x8f, (byte) 0xb8, (byte) 0x7e, (byte) 0x45, (byte) 0xaf,
            (byte) 0xf1, (byte) 0x8d, (byte) 0x9b, (byte) 0xc, (byte) 0xaf,
            (byte) 0x2d };

    public final static byte[] staticPrivateKey = { (byte) 0x3a, (byte) 0x41, (byte) 0x26,
            (byte) 0x1a, (byte) 0xcf, (byte) 0xe1, (byte) 0xe0, (byte) 0x31,
            (byte) 0xf4, (byte) 0xa1, (byte) 0x8b, (byte) 0x24, (byte) 0x85,
            (byte) 0xa4, (byte) 0x97, (byte) 0xdc, (byte) 0x31, (byte) 0xab,
            (byte) 0x75, (byte) 0xc1, (byte) 0x3a, (byte) 0xc, (byte) 0x2,
            (byte) 0xa8, (byte) 0x4f, (byte) 0x52, (byte) 0xa1, (byte) 0xec,
            (byte) 0xa6, (byte) 0x71, (byte) 0xe2, (byte) 0x61 };

    public final static byte[] staticNonce = {
            (byte) 0x3a, (byte) 0x41, (byte) 0x26,
            (byte) 0x1a, (byte) 0xcf, (byte) 0xe1, (byte) 0xe0, (byte) 0x31,
            (byte) 0xf4, (byte) 0xa1, (byte) 0x8b, (byte) 0x24, (byte) 0x85,
            (byte) 0xa4, (byte) 0x97, (byte) 0xdc };

    public final static byte[] staticBionymSignature = { (byte) 0x3a, (byte) 0x41, (byte) 0x26,
            (byte) 0x1a, (byte) 0xcf, (byte) 0xe1, (byte) 0xe0, (byte) 0x31,
            (byte) 0xf4, (byte) 0xa1, (byte) 0x8b, (byte) 0x24, (byte) 0x85,
            (byte) 0xa4, (byte) 0x97, (byte) 0xdc, (byte) 0x31, (byte) 0xab,
            (byte) 0x75, (byte) 0xc1, (byte) 0x3a, (byte) 0xc, (byte) 0x2,
            (byte) 0xa8, (byte) 0x4f, (byte) 0x52, (byte) 0xa1, (byte) 0xec,
            (byte) 0xa6, (byte) 0x71, (byte) 0xe2, (byte) 0x61 };

	// NCL event callbacks
	protected static NclCallback nclCallback;

	// Last RSSI value received
	protected int rssi;

	long startFindingTime = 0L;

	// the current nymi handle
	protected int nymiHandle = -1;

	// the current provision that has been made
	protected NclProvision provision;

	State state;

	Context context;
	GlobalSignListener listener;

    protected NclVkId vkId;
    protected NclVk vkKey;

	/**
	 * Constructor
	 * @param context the context
	 */
	public GlobalSignController(Context context) {
		this.context = context;
	}

	/**
	 * 
	 * @return the current validation process listener
	 */
	public GlobalSignListener getListener() {
		return listener;
	}

	/**
	 * Set the validation process listener
	 * @param listener the listener
	 */
	public void setListener(GlobalSignListener listener) {
		this.listener = listener;
	}

	/**
	 * Get the connected Nymi handler
	 * @return
	 */
	public int getNymiHandle() {
		return nymiHandle;
	}

	/**
	 * 
	 * @return the provisioned provision
	 */
	public NclProvision getProvision() {
		return provision;
	}

	/**
	 * 
	 * @return the current state
	 */
	public State getState() {
		return state;
	}

	/**
	 * Start the validation process
	 */
	protected synchronized boolean startGlobalSign(final GlobalSignListener listener, final NclProvision provision) {
		if (state != null) {
			return false;
		}
		
		this.listener = listener;

        if (nclCallback == null) {
            nclCallback = new MyNclCallback();
        }
        
        Ncl.addBehavior(nclCallback, null, NclEventType.NCL_EVENT_ANY, Ncl.NYMI_HANDLE_ANY);

        nymiHandle = -1;
		this.provision = provision;
		ThreadUtil.runTaskAfterMillies(new Runnable() {
            @Override
            public void run() {
                startFinding();
            }
        }, 0);
		
		return true;
	}

	protected void startFinding() {
		state = State.FINDING;

		Log.d(LOG_TAG, "start scan");
        if (!Ncl.startFinding(new NclProvision[] {provision}, false)) { // Ncl.startFinding(provisions, 1, NclBool.NCL_FALSE)) {
            Log.d(LOG_TAG, "Failed to start Finding");
            state = State.FAILED;
            if (listener != null) {
                listener.onFailure(GlobalSignController.this);
            }
        }
	}
	
	/**
	 * Stop the finding process
	 */
	protected void stopFinding() {
		if (state == State.FINDING || state == State.PARTNER_DISCOVERY) {
			boolean b = Ncl.stopScan();
			Log.d(LOG_TAG, "stop scan: " + b);
		}
	}

    protected void createGlobalSignatureKeyPair() {
        if (state == State.VALIDATED) {
            NclPartnerPublicKey pk = new NclPartnerPublicKey();
            pk.v = staticPublicKey;

            NclSig sig = new NclSig();
            sig.v = staticBionymSignature;

            boolean b = Ncl.createGlobalSigKeyPair(nymiHandle, pk, sig);
            Log.d(LOG_TAG, "Ncl.createGlobalSigKeyPair(): " + b);
        }
    }

    protected void startPartnerAuthentication() {
        if (state == State.PARTNER_DISCOVERY) {
            Log.d(LOG_TAG, "getting ready to call Ncl.globalSign()");

            state = State.GLOBAL_SIGN;

            NclAdv adv = new NclAdv();
            Log.d(LOG_TAG, "getting advertisement");
            Ncl.getAdv(nymiHandle, adv);

            NclPartnerPublicKey pk = new NclPartnerPublicKey();
            pk.v = staticPublicKey;

            NclPartnerPrivateKey pvt = new NclPartnerPrivateKey();
            pvt.v = staticPrivateKey;

            NclMessage terminalNonce = new NclMessage();
            terminalNonce.v = staticNonce;

            NclSig signedNonce = new NclSig();
            Ncl.signAdv(adv, terminalNonce, pvt, signedNonce);

            Log.d(LOG_TAG, "calling Ncl.globalSign()");
            boolean b = Ncl.globalSign(nymiHandle, signedNonce, pk, terminalNonce);
            Log.d(LOG_TAG, "Ncl.globalSign(): " + b);
        }
    }

	/**
	 * This method may be called from different places, as of this, we should not unregister the screen on/off receiver here. 
	 * Neither should we lock the screen.
	 */
	public void finish() {
		Log.d(LOG_TAG, "Finish");
		stop();
		nymiHandle = -1;
	}

	/**
	 * Called to clean up resource after the provision process has ended
	 */
	public void stop() {
        if (nclCallback != null) {
            Ncl.removeBehavior(nclCallback, null, NclEventType.NCL_EVENT_ANY, Ncl.NYMI_HANDLE_ANY);
            nclCallback = null;
        }

        if (state == State.FINDING) {
            state = null;
            Ncl.stopScan();
        }
	}

	/**
	 * Interface for listening on the provision process
	 *
	 */
	public interface GlobalSignListener {
		/**
		 * Called when the provision process is started
		 * @param controller the ValidationController performing the validation
		 */
		public void onStartProcess(GlobalSignController controller);
		
		/**
		 * Called when the provisioned Nymi is found
		 * @param controller the ValidationController performing the validation
		 */
		public void onFound(GlobalSignController controller);
		
		/**
		 * Called when the Nymi is validated
		 * @param controller the ValidationController performing the validation
		 */
		public void onValidated(GlobalSignController controller);
		
		/**
		 * Called when the provision process failed
		 * @param controller the ValidationController performing the validation
		 */
		public void onFailure(GlobalSignController controller);
		
		/**
		 * Called when the connected Nymi during the provision process is disconnected 
		 * @param controller the ValidationController performing the validation
		 */
		public void onDisconnected(GlobalSignController controller);
	}
	
    public class MyNclCallback implements NclCallback {
        @Override
        public void call(final NclEvent event, final Object userData) {
            Log.d(LOG_TAG, this.toString() + ": " + event.getClass().getName());
            if (event instanceof NclEventFind) {
                if (state == State.FINDING) { // finding in progress
                    rssi = ((NclEventFind) event).rssi;
                    if (rssi > RSSI_THRESHOLD) {
                        stopFinding();
                        nymiHandle = ((NclEventFind) event).nymiHandle;
                        if (listener != null) {
                            listener.onFound(GlobalSignController.this);
                        }

                        if (!Ncl.validate(((NclEventFind) event).nymiHandle)) {
                            if (listener != null) {
                                listener.onFailure(GlobalSignController.this);
                            }
                            state = State.FAILED;
                            Log.d("NCL_EVENT_FIND", "Validate failed!");
                        }
                        else {
                            state = State.VALIDATING;
                        }
                    }
                }
            }
            else if (event instanceof NclEventDetection) {
                if (state == State.PARTNER_DISCOVERY) {
                    rssi = ((NclEventDetection)event).rssi;
                    if (rssi > RSSI_THRESHOLD) {
                        stopFinding();
                        nymiHandle = ((NclEventDetection)event).nymiHandle;
                        startPartnerAuthentication();
                    } else {
                        Log.d(LOG_TAG, "rssi of " + rssi + " to low, must be greater than " + RSSI_THRESHOLD);
                    }
                } else {
                    Log.d(LOG_TAG, "unexpected state " + state + " on NCL_EVENT_DETECTION");
                }
            }
            else if (event instanceof NclEventValidation) {
                if (nymiHandle == ((NclEventValidation) event).nymiHandle) {
                    stopFinding();
                    state = State.VALIDATED;
                    if (listener != null) {
                        listener.onValidated(GlobalSignController.this);
                    }

                    createGlobalSignatureKeyPair();
                }
            }
            else if (event instanceof NclEventDisconnection) {
                if (nymiHandle == ((NclEventDisconnection)event).nymiHandle) {
                    // Nymi got disconnected, this might be normal case, just make sure we cleanup Nymi, and release wake lock
                    // However, it can also occur when Nymi connection has failed for whatever reason
                    Log.d(LOG_TAG, "NCL_EVENT_DISCONNECTION validated: " + (state == State.VALIDATED));
                    if (state == State.FINDING || state == State.VALIDATING) {
                        state = State.FAILED;
                        if (listener != null) {
                            listener.onFailure(GlobalSignController.this);
                        }
                    } else if (state == State.GLOBAL_KEYPAIR_CREATED) {
                        Log.d(LOG_TAG, "starting partner discovery");
                        state = State.PARTNER_DISCOVERY;
                        boolean b = Ncl.startFinding(new NclProvision[0], true);
                        Log.d(LOG_TAG, "startFinding(): " + b);
                        return;
                    } else if (state == State.GLOBAL_SIGN) {
                        Log.d(LOG_TAG, "this is the problem, a disconnect after Ncl.globalSign()");
                        state = state.FAILED;
                        if (listener != null) {
                            listener.onFailure(GlobalSignController.this);
                        }
                    }
                    state = null;
                    nymiHandle = -1;
                }
            }
            else if (event instanceof NclEventError) {
                nymiHandle = -1;
                state = State.FAILED;
                if (listener != null) {
                    listener.onFailure(GlobalSignController.this);
                }
                Ncl.removeBehavior(nclCallback, null, NclEventType.NCL_EVENT_ANY, Ncl.NYMI_HANDLE_ANY);
            }
            else if (event instanceof NclEventGlobalVk) {
                Log.d(LOG_TAG, "global signature created");
                vkId = ((NclEventGlobalVk)event).id;
                vkKey = ((NclEventGlobalVk)event).vk;
                state = State.GLOBAL_KEYPAIR_CREATED;
                Ncl.disconnect(nymiHandle);
            }
        }
    }
    
	public enum State {
		CREATED, ///< \brief ready to start provision process
		FINDING, ///< \brief discovery started
        GLOBAL_KEYPAIR_CREATED,
        PARTNER_DISCOVERY,
        GLOBAL_SIGN,
		VALIDATING, ///< \brief agreement in progress, but hasn't finished yet. \warning Stopping provision operation during this state will cause desynchronization between Nymi state and NCL state
		VALIDATED, ///< \brief agreement completed User should call \ref accept or \ref reject based on the \ref leds result
		NO_DEVICE, ///< \brief provision has failed due to no active devices in the area. Make sure the Nymi is nearby and is in provisioning mode
		FAILED, ///< \brief NCL initialization has failed, you may attempt to retry \ref init, but you should check if the ble connector is working first
		NO_BLE, ///< \brief the device has no BLE
		BLE_DISABLED, ///< \brief BLE is disabled
		AIRPLANE_MODE ///< \brief The device is in airplane mode
	}
}
