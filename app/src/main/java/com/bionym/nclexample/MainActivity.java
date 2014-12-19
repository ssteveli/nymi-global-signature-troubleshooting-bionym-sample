package com.bionym.nclexample;

import android.app.Activity;
import android.os.Bundle;
import android.text.Editable;
import android.text.TextWatcher;
import android.util.Log;
import android.view.Menu;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.RadioGroup;
import android.widget.Toast;

import com.bionym.ncl.Ncl;
import com.bionym.ncl.NclCallback;
import com.bionym.ncl.NclEvent;
import com.bionym.ncl.NclEventInit;
import com.bionym.ncl.NclMode;
import com.bionym.ncl.NclProvision;

import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MainActivity extends Activity implements NclCallback,
        ProvisionController.ProvisionProcessListener,
        ValidationController.ValidationProcessListener,
        GlobalSignController.GlobalSignListener {

    protected static final String LOG_TAG = "Nymi Main";

    EditText nymulatorIp;
    RadioGroup selectLibrary;
    Button startProvision, startValidation;
    Button globalSignature;
    //Button disconnect;

    ProvisionController provisionController;
    ValidationController validationController;
    GlobalSignController globalSignController;
    boolean connectNymi = true;

    int nymiHandle = -1;
    NclProvision provision;
    boolean nclInitialized = false;

    static Pattern ipPattern = Pattern.compile("^\\s*\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\s*$");

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
    }

    @Override
    protected void onStart() {
        super.onStart();

        nymulatorIp = (EditText) findViewById(R.id.nymulatorIp);
        selectLibrary = (RadioGroup) findViewById(R.id.selectLib);
        startProvision = (Button) findViewById(R.id.provision);
        startValidation = (Button) findViewById(R.id.validation);
        globalSignature = (Button) findViewById(R.id.globalSignature);
        //disconnect = (Button) findViewById(R.id.disconnect);
        
        selectLibrary.setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener() {
                 @Override
                 public void onCheckedChanged(RadioGroup group, int checkedId) {
                     if (checkedId == R.id.connectNymy) {
                         connectNymi = true;
                     }
                     else {
                         connectNymi = false;
                     }

                     if (connectNymi) {
                         nymulatorIp.setVisibility(View.GONE);
                     }
                     else {
                         nymulatorIp.setVisibility(View.VISIBLE);
                         String ip = nymulatorIp.getText().toString();
                         Matcher matcher = ipPattern.matcher(ip);
                         if (matcher.matches()) {
                             startProvision.setEnabled(true);
                         }
                         else {
                             startProvision.setEnabled(false);
                         }
                     }
                 }
             }
        );

        nymulatorIp.addTextChangedListener(new TextWatcher() {
            @Override
            public void beforeTextChanged(CharSequence s, int start, int count, int after) {
            }

            @Override
            public void onTextChanged(CharSequence s, int start, int before, int count) {
            }

            @Override
            public void afterTextChanged(Editable s) {
                if (!connectNymi) {
                    String ip = nymulatorIp.getText().toString();
                    Matcher matcher = ipPattern.matcher(ip);
                    if (matcher.matches()) {
                        startProvision.setEnabled(true);
                    }
                    else {
                        startProvision.setEnabled(false);
                    }
                }
            }
        });

        startProvision.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                initializeNcl();
                provisionController = new ProvisionController(MainActivity.this);
                provisionController.startProvision(MainActivity.this);
            }
        });

        startValidation.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                initializeNcl();
                validationController = new ValidationController(MainActivity.this);
                validationController.startValidation(MainActivity.this, provisionController.getProvision());
            }
        });

        globalSignature.setEnabled(false);
        globalSignature.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                initializeNcl();
                globalSignController = new GlobalSignController(MainActivity.this);
                globalSignController.startGlobalSign(MainActivity.this, provisionController.getProvision());
            }
        });
        /*
        disconnect.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Log.d(LOG_TAG, "Disconnecting " + nymiHandle);
                if (nymiHandle >= 0) {
                    Log.d(LOG_TAG, "Disconnecting Nymi for real");
                    Ncl.disconnect(nymiHandle);
                    nymiHandle = -1;
                }
            }
        });
        */
    }

    @Override
    protected void onStop() {
        if (nclInitialized && nymiHandle >= 0) {
            Ncl.disconnect(nymiHandle);
        }

        super.onStop();
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        return false;
    }

    /**
     * Initialize the NCL library
     */
    protected void initializeNcl() {
        if (!nclInitialized) {
            if (connectNymi) {
                Log.d(LOG_TAG, "Connected Nymi - init");
                initializeNclForNymiBand();
            }
            else {
                Log.d(LOG_TAG, "Nymulator - init");
                Log.d(LOG_TAG, nymulatorIp.getText().toString().trim());
                initializeNclForNymulator(nymulatorIp.getText().toString().trim());
            }
        }
    }

    /**
     * Process view when NCL library is initialized
     */
    protected void nclInitialized() {
        View selectLibraryContainer = findViewById(R.id.selectLibContainer);
        selectLibraryContainer.setVisibility(View.GONE);
    }

    /**
     * Initialize NCL library for connecting to a Nymi Band
     * @return true if the library is initialized
     */
    protected boolean initializeNclForNymiBand() {
        if (!nclInitialized) {
            nclInitialized = true;
            boolean result = Ncl.init(this, null, "NCLExample", NclMode.NCL_MODE_DEFAULT, this);

            if (!result) { // failed to initialize NCL
                Toast.makeText(MainActivity.this, "Failed to initialize NCL library!", Toast.LENGTH_LONG).show();
                return false;
            }

            nclInitialized();
        }
        return true;
    }

    /**
     * Initialize NCL library for connecting to a Nymulator
     * @param ip the Nymulator's IP address
     * @return true if the library is initialized
     */
    protected boolean initializeNclForNymulator(String ip) {
        if (!nclInitialized) {
            nclInitialized = true;
            Ncl.setIpAndPort(ip, 9089);
            boolean result = Ncl.init(this, null, "NCLExample", NclMode.NCL_MODE_DEFAULT, this);

            if (!result) { // failed to initialize NCL
                Toast.makeText(MainActivity.this, "Failed to initialize NCL library!", Toast.LENGTH_LONG).show();
                return false;
            }

            nclInitialized();
        }

        return true;
    }

    /**
     * Handle NCL call backs
     * @param event the callback event
     * @param userData user data
     */
    public void call(NclEvent event, Object userData) {
        if (event instanceof NclEventInit) {
            if (((NclEventInit)event).success) {
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        Toast.makeText(MainActivity.this, "Failed to initialize NCL library!", Toast.LENGTH_LONG).show();
                    }
                });
            }
        }
    }

    @Override
    public void onStartProcess(ProvisionController controller) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                Toast.makeText(MainActivity.this, "Nymi start provision ..",
                        Toast.LENGTH_LONG).show();
            }
        });
    }

    @Override
    public void onAgreement(final ProvisionController controller) {
        nymiHandle = controller.getNymiHandle();
        controller.accept();
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                Toast.makeText(MainActivity.this, "Agree on pattern: " + Arrays.toString(controller.getLedPatterns()),
                        Toast.LENGTH_LONG).show();
            }
        });
    }

    @Override
    public void onProvisioned(ProvisionController controller) {
        provision = controller.getProvision();
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                startProvision.setEnabled(false);
                startValidation.setEnabled(true);
                globalSignature.setEnabled(true);
                Toast.makeText(MainActivity.this, "Nymi provisioned: " + Arrays.toString(provision.id.v),
                        Toast.LENGTH_LONG).show();
            }
        });
    }

    @Override
    public void onFailure(ProvisionController controller) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                Toast.makeText(MainActivity.this, "Nymi provision failed!",
                        Toast.LENGTH_LONG).show();
            }
        });
    }

    @Override
    public void onDisconnected(ProvisionController controller) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                    startValidation.setEnabled(provision != null);
                    globalSignature.setEnabled(provision != null);
                Toast.makeText(MainActivity.this, "Nymi disconnected: " + provision,
                        Toast.LENGTH_LONG).show();
            }
        });
    }

    @Override
    public void onStartProcess(ValidationController controller) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                Toast.makeText(MainActivity.this, "Nymi start validation for: " + Arrays.toString(provision.id.v),
                        Toast.LENGTH_LONG).show();
            }
        });
    }

    @Override
    public void onFound(ValidationController controller) {
        nymiHandle = controller.getNymiHandle();
        Log.d(LOG_TAG, "Found Nymi handle " + nymiHandle);
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                Toast.makeText(MainActivity.this, "Nymi validation found Nymi on: " + Arrays.toString(provision.id.v),
                        Toast.LENGTH_LONG).show();
            }
        });
    }

    @Override
    public void onValidated(ValidationController controller) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                Toast.makeText(MainActivity.this, "Nymi validated!",
                        Toast.LENGTH_LONG).show();
            }
        });
    }

    @Override
    public void onFailure(ValidationController controller) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                Toast.makeText(MainActivity.this, "Nymi validated failed!",
                        Toast.LENGTH_LONG).show();
            }
        });
    }

    @Override
    public void onDisconnected(ValidationController controller) {
            runOnUiThread(new Runnable() {
            @Override
            public void run() {
                Toast.makeText(MainActivity.this, "Nymi disconnected: " + provision,
                        Toast.LENGTH_LONG).show();
            }
        });
    }

    @Override
    public void onStartProcess(GlobalSignController controller) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                Toast.makeText(MainActivity.this, "Nymi start validation for: " + Arrays.toString(provision.id.v),
                        Toast.LENGTH_LONG).show();
            }
        });
    }

    @Override
    public void onFound(GlobalSignController controller) {
        nymiHandle = controller.getNymiHandle();
        Log.d(LOG_TAG, "Found Nymi handle " + nymiHandle);
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                Toast.makeText(MainActivity.this, "Nymi validation found Nymi on: " + Arrays.toString(provision.id.v),
                        Toast.LENGTH_LONG).show();
            }
        });
    }

    @Override
    public void onValidated(GlobalSignController controller) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                Toast.makeText(MainActivity.this, "Nymi validated!",
                        Toast.LENGTH_LONG).show();
            }
        });
    }

    @Override
    public void onFailure(GlobalSignController controller) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                Toast.makeText(MainActivity.this, "Nymi validated failed!",
                        Toast.LENGTH_LONG).show();
            }
        });
    }

    @Override
    public void onDisconnected(GlobalSignController controller) {
        runOnUiThread(new Runnable() {
            @Override
            public void run() {
                Toast.makeText(MainActivity.this, "Nymi disconnected: " + provision,
                        Toast.LENGTH_LONG).show();
            }
        });
    }
}
