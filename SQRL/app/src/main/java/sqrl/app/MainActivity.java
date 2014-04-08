package sqrl.app;

import android.content.Intent;
import android.os.AsyncTask;
import android.support.v7.app.ActionBarActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;

import com.google.zxing.integration.android.IntentIntegrator;
import com.google.zxing.integration.android.IntentResult;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;


public class MainActivity extends ActionBarActivity {

    private final String logTag = "SQRLTag";
    private TextView tvStatus;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Button scan = (Button) findViewById(R.id.btnScan);

        tvStatus = (TextView) findViewById(R.id.tvStatus);

        scan.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                IntentIntegrator integrator = new IntentIntegrator(MainActivity.this);
                integrator.initiateScan();
            }
        });
    }

    public void onActivityResult(int requestCode, int resultCode, Intent intent) {
        IntentResult scanResult = IntentIntegrator.parseActivityResult(requestCode, resultCode, intent);
        if(scanResult != null) {
            if(scanResult.getContents() != null) {
                Log.d(logTag, scanResult.getContents());
                tvStatus.setText("Logging in at URL\n" + scanResult.getContents());
                new AuthenticationRequestSender().execute(scanResult.getContents());
            }
            else {
                Log.d(logTag, "Scan result contents was null.");
            }
        }
        else {
            Log.d(logTag, "Scan result was null.");
        }
    }


    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        int id = item.getItemId();
        if (id == R.id.action_settings) {
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    private class AuthenticationRequestSender extends AsyncTask<String, Void, Boolean> {

        @Override
        protected Boolean doInBackground(String... params) {
            String url = params[0];
            boolean success;

            // read the private key
            byte[] keyData = readFile(R.raw.pkcs8_key);
            if(keyData == null) {
                return false;
            }

            // sign the url
            String b64Signature = signData(url, keyData);
            if(b64Signature == null) {
                return false;
            }

            // get the public key
            keyData = readFile(R.raw.pubkey);
            if(keyData == null) {
                return false;
            }
            String b64PubKey = encodePublicKey(keyData);

            // send the request
            success = sendRequest(url, b64PubKey, b64Signature);
            return success;
        }

        protected void onPostExecute(Boolean success) {
            if(success) {
                tvStatus.setText("Login successful!");
            }
            else {
                tvStatus.setText("Error during login.");
            }
        }

        private byte[] readFile(int resourceId) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            try {
                InputStream is = getResources().openRawResource(resourceId);
                byte[] buffer = new byte[1024];
                int bytesRead;
                while ((bytesRead = is.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
            } catch (IOException ex) {
                Log.e(logTag, ex.toString());
                return null;
            }
            return out.toByteArray();
        }

        private String signData(String data, byte[] keyData) {
            String encodedSignature;
            byte[] sigData;
            try {
                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyData);
                PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(keySpec);
                Signature signature = Signature.getInstance("SHA256withRSA");
                signature.initSign(privateKey);
                signature.update(data.getBytes());
                sigData = signature.sign();
            } catch (NoSuchAlgorithmException ex) {
                Log.e(logTag, ex.toString());
                return null;
            } catch(InvalidKeyException ex) {
                Log.e(logTag, ex.toString());
                return null;
            } catch (InvalidKeySpecException ex) {
                Log.e(logTag, ex.toString());
                return null;
            } catch(SignatureException ex) {
                Log.e(logTag, ex.toString());
                return null;
            }

            encodedSignature = Base64.encodeToString(sigData, Base64.DEFAULT);
            encodedSignature = encodedSignature.replaceAll("\\n", "");
            return encodedSignature;
        }

        private boolean sendRequest(String url, String pubKey, String signature) {
            boolean success;

            HttpClient client = new DefaultHttpClient();
            HttpPost post = new HttpPost(url);
            List<NameValuePair> postParams = new ArrayList<NameValuePair>();
            postParams.add(new BasicNameValuePair("idk", pubKey));
            postParams.add(new BasicNameValuePair("sig", signature));

            try {
                post.setEntity(new UrlEncodedFormEntity(postParams));
                HttpResponse response = client.execute(post);
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                response.getEntity().writeTo(out);

                String json = out.toString();
                JSONObject object = new JSONObject(json);
                success = object.getBoolean("success");
            } catch(UnsupportedEncodingException ex) {
                Log.e(logTag, ex.toString());
                return false;
            } catch(ClientProtocolException ex) {
                Log.e(logTag, ex.toString());
                return false;
            } catch(IOException ex) {
                Log.e(logTag, ex.toString());
                return false;
            } catch(JSONException ex) {
                Log.e(logTag, ex.toString());
                return false;
            }

            return success;
        }

        private String encodePublicKey(byte[] keyData) {
            String pubKeyString = new String(keyData, Charset.defaultCharset());
            pubKeyString = pubKeyString.replaceAll("\\r\\n", "\n");
            String b64PubKey = Base64.encodeToString(pubKeyString.getBytes(Charset.defaultCharset()), Base64.DEFAULT);
            return b64PubKey.replaceAll("\\n", "");
        }
    }

}
