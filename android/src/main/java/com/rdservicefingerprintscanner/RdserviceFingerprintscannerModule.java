package com.rdservicefingerprintscanner;

import android.app.Activity;
import android.content.Intent;
import android.util.Log;

import androidx.annotation.NonNull;

import com.facebook.react.bridge.Arguments;
import com.facebook.react.bridge.BaseActivityEventListener;
import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.WritableMap;
import com.facebook.react.module.annotations.ReactModule;

import org.json.JSONException;
import org.json.JSONObject;
import fr.arnaudguyon.xmltojsonlib.XmlToJson;

@ReactModule(name = RdserviceFingerprintscannerModule.NAME)
public class RdserviceFingerprintscannerModule extends ReactContextBaseJavaModule implements RDServiceEvents {
  public static final String NAME = "RdserviceFingerprintscanner";
  public Promise promise;
  private RDServiceManager rdServiceManager;
  String servicePackage = "";

  public RdserviceFingerprintscannerModule(ReactApplicationContext reactContext) {
    super(reactContext);
    reactContext.addActivityEventListener(new RDServiceActivityEventListener());
    rdServiceManager = new RDServiceManager.Builder(this).create();
  }

  @Override
  @NonNull
  public String getName() {
    return NAME;
  }

  // ---------------------------------------------------------------------
  // Null-safe promise helpers (a promise is resolved/rejected only once)
  // ---------------------------------------------------------------------
  private synchronized void resolvePromise(Object value) {
    Promise p = promise;
    promise = null;
    if (p != null) {
      try {
        p.resolve(value);
      } catch (Exception e) {
        Log.e(NAME, "resolvePromise failed", e);
      }
    }
  }

  private synchronized void rejectPromise(String code, String message) {
    Promise p = promise;
    promise = null;
    if (p != null) {
      try {
        p.reject(code, message);
      } catch (Exception e) {
        Log.e(NAME, "rejectPromise failed", e);
      }
    }
  }

  // ---------------------------------------------------------------------
  // React methods
  // ---------------------------------------------------------------------
  @ReactMethod
  public void getDeviceInfo(Promise promise) {
    this.promise = promise;
    final Activity activity = getCurrentActivity();
    if (activity == null) {
      rejectPromise("NO_ACTIVITY", "Activity is not available");
      return;
    }
    rdServiceManager.discoverRdService(activity);
  }

  @ReactMethod
  public void isDriverFound(String packageName, Promise promise) {
    this.promise = promise;
    final Activity activity = getCurrentActivity();
    if (activity == null) {
      rejectPromise("NO_ACTIVITY", "Activity is not available");
      return;
    }
    rdServiceManager.isDriverFound(packageName, activity);
  }

  @ReactMethod
  public void openFingerPrintScanner(String packageName, String pidOptions, Promise promise) {
    this.promise = promise;
    final Activity activity = getCurrentActivity();
    if (activity == null) {
      rejectPromise("NO_ACTIVITY", "Activity is not available");
      return;
    }
    rdServiceManager.openFingerPrintScanner(packageName, pidOptions, activity);
  }

  @ReactMethod
  public void openFaceAuth(String transactionId, Promise promise) {
    this.promise = promise;
    final Activity activity = getCurrentActivity();
    if (activity == null) {
      rejectPromise("NO_ACTIVITY", "Activity is not available");
      return;
    }
    rdServiceManager.openFaceAuth(transactionId, activity);
  }

  @ReactMethod
  public void captureFinger(String pidOptions, Promise promise) {
    this.promise = promise;
    final Activity activity = getCurrentActivity();
    if (activity == null) {
      rejectPromise("NO_ACTIVITY", "Activity is not available");
      return;
    }
    rdServiceManager.captureRdService(servicePackage, pidOptions, activity);
  }

  // ---------------------------------------------------------------------
  // RDServiceEvents callbacks
  // ---------------------------------------------------------------------
  @Override
  public void onDeviceDriverFound(Boolean isFound) {
    try {
      WritableMap responseData = Arguments.createMap();
      responseData.putBoolean("isDeviceDriverFound", isFound);
      responseData.putInt("status", isFound ? 1 : 0);
      responseData.putString("message", isFound ? "Device Driver is Discovered" : "Device Driver not found");
      resolvePromise(responseData);
    } catch (Exception e) {
      rejectPromise("DRIVER_FOUND_ERROR", e.getMessage());
    }
  }

  @Override
  public void onRDServiceDriverDiscovery(String rdServiceInfo, String rdServicePackage, Boolean isWhitelisted) {
    // Called when an installed driver is discovered
    servicePackage = rdServicePackage;
    try {
      XmlToJson xmlToJson = new XmlToJson.Builder(rdServiceInfo).build();
      String jsonString = xmlToJson.toString();

      JSONObject obj = new JSONObject(jsonString);
      String statusMsg = obj.getJSONObject("RDService").getString("status");
      WritableMap responseData = Arguments.createMap();
      if (statusMsg.equals("READY")) {
        responseData.putInt("status", 1);
        responseData.putString("message", "Device is Ready");
      } else {
        responseData.putInt("status", 0);
        responseData.putString("message", "Make Sure the Device is Connected and OTG Connection is Enabled in your Mobile");
      }
      responseData.putString("rdSerciceInfoJsonString", jsonString);
      responseData.putString("rdserviceInfoXML", rdServiceInfo);
      responseData.putString("rdServicepackage", rdServicePackage);
      responseData.putBoolean("isWhitelisted", isWhitelisted);
      resolvePromise(responseData);
    } catch (Exception e) {
      rejectPromise("DRIVER_DISCOVERY_FAILED", "Driver Discovery Failed");
    }
  }

  @Override
  public void onRDServiceCaptureResponse(String pidData, String rdServicePackage) {
    try {
      XmlToJson xmlToJson = new XmlToJson.Builder(pidData).build();
      String jsonString = xmlToJson.toString();

      JSONObject obj = new JSONObject(jsonString);
      JSONObject response = obj.getJSONObject("PidData").getJSONObject("Resp");
      String errorCode = response.getString("errCode");
      String errInfo = "";
      WritableMap responseData = Arguments.createMap();
      if (Integer.parseInt(errorCode) == 0) {
        responseData.putInt("status", 1);
        responseData.putString("message", "FingerPrint Scanned Successfully");
      } else {
        errInfo = response.optString("errInfo", "");
        responseData.putInt("status", 0);
        responseData.putString("message", "Make Sure the Device is Connected and OTG Connection is Enabled in your Mobile");
      }

      responseData.putString("errorCode", errorCode);
      responseData.putString("errInfo", errInfo);
      responseData.putString("piddataJsonString", jsonString);
      responseData.putString("piddataXML", pidData);
      responseData.putString("rdservicePackage", rdServicePackage);
      resolvePromise(responseData);
    } catch (Exception e) {
      rejectPromise("FINGERPRINT_CAPTURE__FAILED", "FingerPrint Capture Failed");
    }
  }

  @Override
  public void onRDServiceDriverNotFound() {
    // Called when no installed driver is found
    WritableMap responseData = Arguments.createMap();
    responseData.putInt("status", -1);
    responseData.putString("message", "Driver Not Found");
    resolvePromise(responseData);
  }

  @Override
  public void onRDServiceDriverDiscoveryFailed(int resultCode, Intent data, String rdServicePackage, String reason) {
    // Called when a discovered driver fails to provide proper status information
    rejectPromise("DRIVER_DISCOVERY_FAILED", "Driver Discovery Failed");
  }

  @Override
  public void onRDServiceCaptureFailed(int resultCode, Intent data, String rdServicePackage) {
    // Called when fingerprint capture fails
    rejectPromise("FINGERPRINT_CAPTURE__FAILED", "FingerPrint Capture Failed");
  }

  private class RDServiceActivityEventListener extends BaseActivityEventListener {
    @Override
    public void onActivityResult(Activity activity, int requestCode, int resultCode, Intent data) {
      super.onActivityResult(activity, requestCode, resultCode, data);
      try {
        rdServiceManager.onActivityResult(requestCode, resultCode, data);
      } catch (Exception e) {
        Log.e(NAME, "onActivityResult error", e);
      }
    }
  }
}
