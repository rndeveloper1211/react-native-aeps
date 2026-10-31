package com.rdservicefingerprintscanner;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.ResolveInfo;
import android.os.Bundle;
import android.util.Log;

import androidx.annotation.NonNull;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static android.app.Activity.RESULT_OK;

/**
 * Helper class to help capture fingerprint data by using RDService drivers.
 */
public class RDServiceManager {

    private static final String TAG = "RDServiceManager";
    private RDServiceEvents mRDEvent;

    private static final int RC_RDSERVICE_DISCOVER_START_INDEX = 8500;
    private static final int RC_RDSERVICE_CAPTURE_START_INDEX = 8300;
    private static final int FACE_AUTH_RESPONSE = 7777;
    private static final int FINGERPRINT_SCANNER_CAPTURE = 8761;

    private static final Map<String, Integer> mapRDDriverRCIndex = new HashMap<String, Integer>();
    private static final Map<Integer, String> mapRDDiscoverRC = new HashMap<Integer, String>();
    private static final Map<Integer, String> mapRDCaptureRC = new HashMap<Integer, String>();

    private static final Map<String, String> mapRDDriverWhitelist = new HashMap<String, String>() {
        {
            put("com.secugen.rdservice", "Secugen");
            put("com.scl.rdservice", "Morpho");
            put("com.mantra.rdservice", "Mantra");
            put("com.acpl.registersdk", "Startek FM220");
            put("com.rd.gemalto.com.rdserviceapp", "Gemalto 3M Cogent CSD200");
            put("com.acpl.registersdk_l1", "Startek L1");
            put("com.integra.registered.device", "Integra");
            put("com.aratek.asix_gms.rdservice", "Aratek");
            put("rdservice.metsl.metslrdservice", "Maestros");
            put("com.tatvik.bio.tmf20", "Tatvik TMF20");
            put("com.evolute.rdservice", "Evolute");
            put("com.precision.pb510.rdservice", "PB510");
            put("com.mantra.mis100v2.rdservice", "MIS100V2 by Mantra");
            put("com.mantra.mfs110.rdservice", "MFS110 by Mantra");
            put("com.nextbiometrics.rdservice", "NEXT Biometrics NB-3023");
            put("com.iritech.rdservice", "IriTech IriShield");
            put("com.evolute.iris.rdservice", "Evolute IRIS");
        }
    };

    private static final Map<String, String> mapRDDriverBlacklist = new HashMap<String, String>();

    private RDServiceManager(@NonNull final Builder builder) {
        mRDEvent = builder._rdevent;
        mapRDDriverWhitelist.putAll(builder.mapNewWhitelistedRDDrivers);
        mapRDDriverBlacklist.putAll(builder.mapBlacklistedRDDrivers);
    }

    public static class Builder {
        private RDServiceEvents _rdevent = null;
        private Map<String, String> mapNewWhitelistedRDDrivers = new HashMap<String, String>();
        private Map<String, String> mapBlacklistedRDDrivers = new HashMap<String, String>();

        public Builder(@NonNull final RDServiceEvents eventActivity) {
            _rdevent = eventActivity;
        }

        public Builder whitelistRDDrivers(@NonNull final Map<String, String> mapNewWhitelistedRDDrivers) {
            this.mapNewWhitelistedRDDrivers = mapNewWhitelistedRDDrivers;
            return this;
        }

        public Builder blacklistRDDrivers(@NonNull final Map<String, String> mapBlacklistedRDDrivers) {
            this.mapBlacklistedRDDrivers = mapBlacklistedRDDrivers;
            return this;
        }

        public RDServiceManager create() {
            if (_rdevent == null) {
                throw new IllegalStateException("First set your Activity that implements RDServiceEvent");
            }
            return new RDServiceManager(this);
        }
    }

    /**
     * Handles activity results. Results that do not belong to the RD service
     * (for example Credopay's request code 100) are ignored.
     */
    public void onActivityResult(int requestCode, int resultCode, Intent data) {
        // Ignore results that belong to other modules/SDKs
        boolean isRdRequest =
                requestCode == FACE_AUTH_RESPONSE
                || requestCode == FINGERPRINT_SCANNER_CAPTURE
                || mapRDDiscoverRC.containsKey(requestCode)
                || mapRDCaptureRC.containsKey(requestCode);
        if (!isRdRequest) {
            return;
        }

        if (requestCode == FACE_AUTH_RESPONSE) {
            if (resultCode == RESULT_OK && data != null) {
                onRDFaceCaptureIntentResponse(data, "FACE_SCANNER");
            } else {
                mRDEvent.onRDServiceCaptureFailed(resultCode, data, "FACE_AUTH_FAILED");
            }
            return;
        }

        if (requestCode == FINGERPRINT_SCANNER_CAPTURE) {
            if (resultCode == RESULT_OK && data != null) {
                onRDServiceCaptureIntentResponse(data, "FINGERPRINT_SCANNER");
            } else {
                mRDEvent.onRDServiceCaptureFailed(resultCode, data, "CAPTURE_FAILED");
            }
            return;
        }

        if (mapRDDiscoverRC.containsKey(requestCode)) {
            String rdservice_pkg_name = mapRDDiscoverRC.get(requestCode);
            if (resultCode == RESULT_OK && data != null) {
                onRDServiceInfoResponse(data, rdservice_pkg_name);
            } else {
                mRDEvent.onRDServiceDriverDiscoveryFailed(resultCode, data, rdservice_pkg_name, "Discovery Failed");
            }
        } else if (mapRDCaptureRC.containsKey(requestCode)) {
            String rdservice_pkg_name = mapRDCaptureRC.get(requestCode);
            if (resultCode == RESULT_OK && data != null) {
                onRDServiceCaptureIntentResponse(data, rdservice_pkg_name);
            } else {
                mRDEvent.onRDServiceCaptureFailed(resultCode, data, rdservice_pkg_name);
            }
        }
    }

    private boolean isDeviceDriverFound(String packageName, Activity activity) {
        if (activity == null || packageName == null) {
            return false;
        }
        Intent intentServiceList = new Intent("in.gov.uidai.rdservice.fp.INFO");
        List<ResolveInfo> resolveInfoList = activity.getPackageManager().queryIntentActivities(intentServiceList, 0);
        if (resolveInfoList.isEmpty()) {
            return false;
        }
        for (ResolveInfo resolveInfo : resolveInfoList) {
            if (packageName.equals(resolveInfo.activityInfo.packageName)) {
                return true;
            }
        }
        return false;
    }

    public void isDriverFound(String packageName, Activity activity) {
        mRDEvent.onDeviceDriverFound(isDeviceDriverFound(packageName, activity));
    }

    public void openFingerPrintScanner(String packageName, String pid_options, Activity activity) {
        if (isDeviceDriverFound(packageName, activity)) {
            Intent intentCapture = new Intent("in.gov.uidai.rdservice.fp.CAPTURE");
            intentCapture.setPackage(packageName);
            intentCapture.putExtra("PID_OPTIONS", pid_options);
            activity.startActivityForResult(intentCapture, FINGERPRINT_SCANNER_CAPTURE);
        } else {
            mRDEvent.onDeviceDriverFound(false);
        }
    }

    public void openFaceAuth(String transactionId, Activity activity) {
        try {
            Intent intent = new Intent("in.gov.uidai.rdservice.face.CAPTURE");

            intent.putExtra("request",
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
                    "<PidOptions ver=\"1.0\" env=\"P\">\n" +
                    "<Opts fType=\"2\" pidVer=\"2.0\" />\n" +
                    "<CustOpts>\n" +
                    "<Param name=\"txnId\" value=\"" + transactionId + "\"/>\n" +
                    "</CustOpts>\n" +
                    "</PidOptions>");

            activity.startActivityForResult(intent, FACE_AUTH_RESPONSE);
        } catch (Exception e) {
            e.printStackTrace();
            mRDEvent.onRDServiceDriverDiscoveryFailed(0, null, "UIDAI", e.getMessage());
        }
    }

    public void discoverRdService(Activity activity) {
        Intent intentServiceList = new Intent("in.gov.uidai.rdservice.fp.INFO");
        List<ResolveInfo> resolveInfoList = activity.getPackageManager().queryIntentActivities(intentServiceList, 0);
        if (resolveInfoList.isEmpty()) {
            mRDEvent.onRDServiceDriverNotFound();
            return;
        }

        int index = 1;
        for (ResolveInfo resolveInfo : resolveInfoList) {
            String _pkg = resolveInfo.activityInfo.packageName;

            if (!mapRDDriverBlacklist.containsKey(_pkg)) {
                try {
                    mapRDDriverRCIndex.put(_pkg, index);
                    int next_discover_rc_index = getRDServiceDiscoverRC(index);
                    mapRDDiscoverRC.put(next_discover_rc_index, _pkg);
                    int next_capture_rc_index = getRDServiceCaptureRC(index);
                    mapRDCaptureRC.put(next_capture_rc_index, _pkg);

                    Intent intentInfo = new Intent("in.gov.uidai.rdservice.fp.INFO");
                    intentInfo.setPackage(_pkg);
                    activity.startActivityForResult(intentInfo, next_discover_rc_index);

                } catch (Exception e) {
                    mRDEvent.onRDServiceDriverDiscoveryFailed(0, null, _pkg, e.getMessage());
                }
            }
            if (index++ >= 10) break;
        }
    }

    public void captureRdService(@NonNull String rd_service_package, @NonNull String pid_options, Activity activity) {
        if (mapRDDriverRCIndex.containsKey(rd_service_package)) {
            int capture_rc_index = mapRDDriverRCIndex.get(rd_service_package);
            int capture_rc = getRDServiceCaptureRC(capture_rc_index);

            Intent intentCapture = new Intent("in.gov.uidai.rdservice.fp.CAPTURE");
            intentCapture.setPackage(rd_service_package);
            intentCapture.putExtra("PID_OPTIONS", pid_options);

            activity.startActivityForResult(intentCapture, capture_rc);
        } else {
            mRDEvent.onRDServiceDriverDiscoveryFailed(0, null, rd_service_package, "Package not found");
        }
    }

    private void onRDServiceInfoResponse(@NonNull Intent data, @NonNull String rd_service_package) {
        Bundle b = data.getExtras();
        if (b != null) {
            mRDEvent.onRDServiceDriverDiscovery(b.getString("RD_SERVICE_INFO", ""), rd_service_package, mapRDDriverWhitelist.containsKey(rd_service_package));
        } else {
            mRDEvent.onRDServiceDriverDiscoveryFailed(0, data, rd_service_package, "Empty response");
        }
    }

    private void onRDServiceCaptureIntentResponse(@NonNull Intent data, @NonNull String rd_service_package) {
        Bundle b = data.getExtras();
        if (b != null) {
            mRDEvent.onRDServiceCaptureResponse(b.getString("PID_DATA", ""), rd_service_package);
        } else {
            mRDEvent.onRDServiceCaptureFailed(0, data, rd_service_package);
        }
    }

    private void onRDFaceCaptureIntentResponse(@NonNull Intent data, @NonNull String rd_service_package) {
        // Face auth uses the "response" key, not "PID_DATA"
        String response = data.getStringExtra("response");
        if (response != null) {
            mRDEvent.onRDServiceCaptureResponse(response, rd_service_package);
        } else {
            mRDEvent.onRDServiceCaptureFailed(0, data, rd_service_package);
        }
    }

    private int getRDServiceDiscoverRC(int index) {
        return RC_RDSERVICE_DISCOVER_START_INDEX + index;
    }

    private int getRDServiceCaptureRC(int index) {
        return RC_RDSERVICE_CAPTURE_START_INDEX + index;
    }
}
