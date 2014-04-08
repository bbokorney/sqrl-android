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
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.message.BasicNameValuePair;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
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
                tvStatus.setText("Logging in a URL\n" + scanResult.getContents());
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
        
        // Inflate the menu; this adds items to the action bar if it is present.
        getMenuInflater().inflate(R.menu.main, menu);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        // Handle action bar item clicks here. The action bar will
        // automatically handle clicks on the Home/Up button, so long
        // as you specify a parent activity in AndroidManifest.xml.
        int id = item.getItemId();
        if (id == R.id.action_settings) {
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    private class AuthenticationRequestSender extends AsyncTask<String, Void, Boolean> {

        @Override
        protected Boolean doInBackground(String... params) {
            boolean success = true;
            try {
                InputStream is = getResources().openRawResource(R.raw.pkcs8_key);

                byte[] keyData = new byte[is.available()]; // TODO: read entire file at once
                is.read(keyData);

                PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyData);
                PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(keySpec);
                Signature signature = Signature.getInstance("SHA256withRSA");
                signature.initSign(privateKey);
                signature.update(params[0].getBytes());
                byte[] sigData = signature.sign();
                String b64Signature = Base64.encodeToString(sigData, Base64.DEFAULT);
                b64Signature = b64Signature.replaceAll("\\n", "");
                Log.d(logTag, b64Signature);



                is = getResources().openRawResource(R.raw.pubkey);
                keyData = new byte[is.available()];
                is.read(keyData);


                String fileString = new String(keyData, Charset.defaultCharset());
                fileString = fileString.replaceAll("\\r\\n", "\n");
                
                Log.d(logTag, "The filestring:");
                Log.d(logTag, fileString);

                //System.out.println(fileString);

                //System.out.println("Base 64 public key:");
                String b64PubKey = Base64.encodeToString(fileString.getBytes(Charset.defaultCharset()), Base64.DEFAULT);
                b64PubKey = b64PubKey.replaceAll("\\n", "");

                HttpClient client = new DefaultHttpClient();
                HttpPost post = new HttpPost(params[0]);
                List<NameValuePair> postParams = new ArrayList<NameValuePair>();
                postParams.add(new BasicNameValuePair("idk", b64PubKey));
                postParams.add(new BasicNameValuePair("sig", b64Signature));

                post.setEntity(new UrlEncodedFormEntity(postParams));
                HttpResponse response = client.execute(post);
                System.out.println(response.getStatusLine());
                ByteArrayOutputStream out = new ByteArrayOutputStream();
                response.getEntity().writeTo(out);

                String json = out.toString();
                System.out.println(json);
            }
            catch(Exception ex) {
                success = false;
                Log.e(logTag, ex.toString());
            }
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
    }

}
