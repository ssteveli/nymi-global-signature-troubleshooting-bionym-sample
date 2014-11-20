package com.bionym.nclexample;

import android.content.Context;
import android.util.Log;

import com.bionym.ncl.Callbacks;
import com.bionym.ncl.Ncl;
import com.bionym.ncl.NclBool;
import com.bionym.ncl.NclCallback;
import com.bionym.ncl.NclEvent;
import com.bionym.ncl.NclEventType;
import com.bionym.ncl.NclProvision;

public class GlobalSignController {
	// Constants
	protected static final String LOG_TAG = "Nymi NCA GlobalSignController";
	protected static final int RSSI_THRESHOLD = -60; // the minimal RSSI for accepting a Nymi, this seems to be more reasonable for one sample due to fluctuation

    public final static char[] staticPublicKey = { (char) 0x71, (char) 0x88, (char) 0xee,
            (char) 0xb, (char) 0xf4, (char) 0xd2, (char) 0xe1, (char) 0x74,
            (char) 0xca, (char) 0x5e, (char) 0x29, (char) 0x50, (char) 0xe7,
            (char) 0xaa, (char) 0x24, (char) 0x7d, (char) 0x8a, (char) 0xe8,
            (char) 0xf0, (char) 0x76, (char) 0x95, (char) 0x5, (char) 0xea,
            (char) 0x9d, (char) 0xf1, (char) 0xc6, (char) 0xd1, (char) 0xa6,
            (char) 0x10, (char) 0x55, (char) 0xdb, (char) 0x2, (char) 0xed,
            (char) 0x60, (char) 0x1c, (char) 0xa0, (char) 0x7c, (char) 0xa4,
            (char) 0x9e, (char) 0x52, (char) 0xf8, (char) 0x0, (char) 0xa5,
            (char) 0xec, (char) 0xf9, (char) 0xac, (char) 0x54, (char) 0xfa,
            (char) 0xac, (char) 0xff, (char) 0x4f, (char) 0x44, (char) 0x19,
            (char) 0x8f, (char) 0xb8, (char) 0x7e, (char) 0x45, (char) 0xaf,
            (char) 0xf1, (char) 0x8d, (char) 0x9b, (char) 0xc, (char) 0xaf,
            (char) 0x2d };

    public final static char[] staticPrivateKey = { (char) 0x3a, (char) 0x41, (char) 0x26,
            (char) 0x1a, (char) 0xcf, (char) 0xe1, (char) 0xe0, (char) 0x31,
            (char) 0xf4, (char) 0xa1, (char) 0x8b, (char) 0x24, (char) 0x85,
            (char) 0xa4, (char) 0x97, (char) 0xdc, (char) 0x31, (char) 0xab,
            (char) 0x75, (char) 0xc1, (char) 0x3a, (char) 0xc, (char) 0x2,
            (char) 0xa8, (char) 0x4f, (char) 0x52, (char) 0xa1, (char) 0xec,
            (char) 0xa6, (char) 0x71, (char) 0xe2, (char) 0x61 };

    public final static char[] staticNonce = {
            (char) 0x3a, (char) 0x41, (char) 0x26,
            (char) 0x1a, (char) 0xcf, (char) 0xe1, (char) 0xe0, (char) 0x31,
            (char) 0xf4, (char) 0xa1, (char) 0x8b, (char) 0x24, (char) 0x85,
            (char) 0xa4, (char) 0x97, (char) 0xdc };

    public final static char[] staticBionymSignature = { (char) 0x3a, (char) 0x41, (char) 0x26,
            (char) 0x1a, (char) 0xcf, (char) 0xe1, (char) 0xe0, (char) 0x31,
            (char) 0xf4, (char) 0xa1, (char) 0x8b, (char) 0x24, (char) 0x85,
            (char) 0xa4, (char) 0x97, (char) 0xdc, (char) 0x31, (char) 0xab,
            (char) 0x75, (char) 0xc1, (char) 0x3a, (char) 0xc, (char) 0x2,
            (char) 0xa8, (char) 0x4f, (char) 0x52, (char) 0xa1, (char) 0xec,
            (char) 0xa6, (char) 0x71, (char) 0xe2, (char) 0x61 };

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

    protected char[] vkId;
    protected char[] vkKey;

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

        nclCallback = new NclCallback(this, "handleCallBack", NclEventType.NCL_EVENT_ANY);
        boolean result = Ncl.addBehavior(nclCallback);

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
        if (!Ncl.startFinding(provision.key, provision.id)) { // Ncl.startFinding(provisions, 1, NclBool.NCL_FALSE)) {
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
            boolean b = Ncl.createGlobalSigKeyPair(nymiHandle, staticPublicKey, staticBionymSignature);
            Log.d(LOG_TAG, "Ncl.createGlobalSigKeyPair(): " + b);
        }
    }

    protected void startPartnerAuthentication() {
        if (state == State.PARTNER_DISCOVERY) {
            state = State.GLOBAL_SIGN;
            char[] adv = Ncl.getAdvertisment(nymiHandle);
            char[] signedNonce = Ncl.signAdvertisment(adv, staticNonce, staticPrivateKey);

            boolean b = Ncl.globalSign(nymiHandle, signedNonce, staticPublicKey, staticNonce);
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
            Callbacks.removeCallBack(nclCallback);
            nclCallback = null;
        }

        if (state == State.FINDING) {
            state = null;
            Ncl.stopScan();
        }
	}

	/**
	 * Handle NCL event callback
	 * @param event the event
	 * @param userData userData registered
	 */
	@SuppressWarnings("unused")
	public synchronized void handleCallBack(NclEvent event, Object userData) {
		switch (event.type) {
        case NCL_EVENT_FIND:
            Log.d(LOG_TAG, "NCL_EVENT_FIND" + " nymiHandle: " + event.find.nymiHandle);
            if (state == State.FINDING) { // finding in progress
                rssi = event.find.rssi;
                if (rssi > RSSI_THRESHOLD) {
                    stopFinding();
                    nymiHandle = event.validation.nymiHandle;
                    if (listener != null) {
                        listener.onFound(this);
                    }
                    if (!Ncl.validate(event.find.nymiHandle)) {
                        if (listener != null) {
                            listener.onFailure(this);
                        }
                        state = State.FAILED;
                        Log.d("NCL_EVENT_FIND", "Validate failed!");
                    }
                    else {
                        state = State.VALIDATING;
                    }
                }
            }
            break;
        case NCL_EVENT_DETECTION:
            if (state == State.PARTNER_DISCOVERY) {
                rssi = event.find.rssi;
                if (rssi > RSSI_THRESHOLD) {
                    stopFinding();
                    nymiHandle = event.detection.nymiHandle;
                    startPartnerAuthentication();
                } else {
                    Log.d(LOG_TAG, "rssi of " + rssi + " to low, must be greater than " + RSSI_THRESHOLD);
                }
            } else {
                Log.d(LOG_TAG, "unexpected state " + state + " on NCL_EVENT_DETECTION");
            }
            break;
        case NCL_EVENT_VALIDATION: // Nymi is validated, end the finding process, disconnect Nymi, and now you can login your user
            Log.d("NCL_EVENT_VALIDATION", "Validated in (millies): " + (System.currentTimeMillis() - startFindingTime));
            nymiHandle = event.validation.nymiHandle;
            stopFinding();
            state = State.VALIDATED;
            if (listener != null) {
                listener.onValidated(this);
            }
            createGlobalSignatureKeyPair();
            break;
        case NCL_EVENT_GLOBAL_VK:
            Log.d(LOG_TAG, "global signature created");
            vkId = event.globalVk.id;
            vkKey = event.globalVk.vk;
            state = State.GLOBAL_KEYPAIR_CREATED;
            Ncl.disconnect(nymiHandle);
            break;
        case NCL_EVENT_DISCONNECTION:
            if (nymiHandle == event.disconnection.nymiHandle) {
                // Nymi got disconnected, this might be normal case, just make sure we cleanup Nymi, and release wake lock
                // However, it can also occur when Nymi connection has failed for whatever reason
                Log.d(LOG_TAG, "NCL_EVENT_DISCONNECTION validated: " + (state == State.VALIDATED));
                if (state == State.FINDING || state == State.VALIDATING) {
                    state = State.FAILED;
                    if (listener != null) {
                        listener.onFailure(this);
                    }
                } else if (state == State.GLOBAL_KEYPAIR_CREATED) {
                    Log.d(LOG_TAG, "starting partner discovery");
                    state = State.PARTNER_DISCOVERY;
                    boolean b = Ncl.startFinding(null, 0, NclBool.NCL_TRUE);
                    Log.d(LOG_TAG, "startFinding(): " + b);
                    break;
                } else if (state == State.GLOBAL_SIGN) {
                    Log.d(LOG_TAG, "this is the problem, a disconnect after Ncl.globalSign()");
                    state = state.FAILED;
                    if (listener != null) {
                        listener.onFailure(this);
                    }
                }
                state = null;
                nymiHandle = -1;
            }
            break;
        case NCL_EVENT_ERROR:
            if (nymiHandle == event.disconnection.nymiHandle) {
                // We got an error, make sure we cleanup Nymi, and release wake lock
                Log.d(LOG_TAG, "NCL_EVENT_ERROR");
                nymiHandle = -1;
                state = State.FAILED;
                if (listener != null) {
                    listener.onFailure(this);
                }
            }
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
