package com.bionym.nclexample;

import com.bionym.ncl.Callbacks;
import com.bionym.ncl.Ncl;
import com.bionym.ncl.NclCallback;
import com.bionym.ncl.NclEvent;
import com.bionym.ncl.NclEventType;
import com.bionym.ncl.NclProvision;

import android.content.Context;
import android.util.Log;

public class ValidationController {
	// Constants
	protected static final String LOG_TAG = "Nymi NCA ValidationController";
	protected static final int RSSI_THRESHOLD = -60; // the minimal RSSI for accepting a Nymi, this seems to be more reasonable for one sample due to fluctuation
	
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
	ValidationProcessListener listener;
	
	/**
	 * Constructor
	 * @param context the context
	 */
	public ValidationController(Context context) {
		this.context = context;
	}

	/**
	 * 
	 * @return the current validation process listener
	 */
	public ValidationProcessListener getListener() {
		return listener;
	}

	/**
	 * Set the validation process listener
	 * @param listener the listener
	 */
	public void setListener(ValidationProcessListener listener) {
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
	protected synchronized boolean startValidation(final ValidationProcessListener listener, final NclProvision provision) {
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
                listener.onFailure(ValidationController.this);
            }
        }
	}
	
	/**
	 * Stop the finding process
	 */
	protected void stopFinding() {
		if (state == State.FINDING) {
			boolean b = Ncl.stopScan();
			Log.d(LOG_TAG, "stop scan: " + b);
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
        case NCL_EVENT_VALIDATION: // Nymi is validated, end the finding process, disconnect Nymi, and now you can login your user
            Log.d("NCL_EVENT_VALIDATION", "Validated in (millies): " + (System.currentTimeMillis() - startFindingTime));
            nymiHandle = event.validation.nymiHandle;
            stopFinding();
            state = State.VALIDATED;
            if (listener != null) {
                listener.onValidated(this);
            }
            // Disconnect right away once validated. Remove this Ncl.disconnect() if you want to maintain the connection to the Nymi and do more with it
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
	public interface ValidationProcessListener {
		/**
		 * Called when the provision process is started
		 * @param controller the ValidationController performing the validation
		 */
		public void onStartProcess(ValidationController controller);
		
		/**
		 * Called when the provisioned Nymi is found
		 * @param controller the ValidationController performing the validation
		 */
		public void onFound(ValidationController controller);
		
		/**
		 * Called when the Nymi is validated
		 * @param controller the ValidationController performing the validation
		 */
		public void onValidated(ValidationController controller);
		
		/**
		 * Called when the provision process failed
		 * @param controller the ValidationController performing the validation
		 */
		public void onFailure(ValidationController controller);
		
		/**
		 * Called when the connected Nymi during the provision process is disconnected 
		 * @param controller the ValidationController performing the validation
		 */
		public void onDisconnected(ValidationController controller);
	}
	
	public enum State {
		CREATED, ///< \brief ready to start provision process
		FINDING, ///< \brief discovery started
		VALIDATING, ///< \brief agreement in progress, but hasn't finished yet. \warning Stopping provision operation during this state will cause desynchronization between Nymi state and NCL state
		VALIDATED, ///< \brief agreement completed User should call \ref accept or \ref reject based on the \ref leds result
		NO_DEVICE, ///< \brief provision has failed due to no active devices in the area. Make sure the Nymi is nearby and is in provisioning mode
		FAILED, ///< \brief NCL initialization has failed, you may attempt to retry \ref init, but you should check if the ble connector is working first
		NO_BLE, ///< \brief the device has no BLE
		BLE_DISABLED, ///< \brief BLE is disabled
		AIRPLANE_MODE ///< \brief The device is in airplane mode
	}
}
