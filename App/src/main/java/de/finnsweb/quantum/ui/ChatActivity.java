package de.finnsweb.quantum.ui;

import androidx.appcompat.app.AppCompatActivity;
import androidx.room.Database;
import de.finnsweb.quantum.R;
import de.finnsweb.quantum.storage.DatabaseManager;
import de.finnsweb.quantum.storage.Message;

import android.os.Bundle;
import android.util.Log;
import android.view.View;
import android.widget.EditText;
import android.widget.TextView;

import java.util.List;

public class ChatActivity extends AppCompatActivity {

    private long chatId = -1;
    TextView tv;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        setContentView(R.layout.activity_chat);
        Bundle args = getIntent().getExtras();

        if(args!=null)
            chatId = args.getLong("de.finnsweb.quantum.ui.chatid",-1);

        if(chatId==-1) finish();

        getSupportActionBar().setTitle("Chat: "+chatId);

        new Thread(new Runnable() {
            @Override
            public void run() {
                final List<Message> messages = DatabaseManager.messageDAO().getAllMessagesFromChat(chatId);
                Log.d("FINN", ""+messages.size());
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        tv = findViewById(R.id.messageTextView);

                        StringBuilder toDisplay = new StringBuilder();
                        for (Message message : messages) {
                            toDisplay.append(message.toString()).append("\n");
                        }
                        tv.setText(toDisplay.toString());
                    }
                });

            }
        }).start();

    }

    public void onSendButtonPressed(View v){
        Message msg = new Message();
        msg.content = ((EditText)findViewById(R.id.messageText)).getText().toString();
        ((EditText)findViewById(R.id.messageText)).setText("");
        msg.timestamp = System.currentTimeMillis();
        msg.direction = Message.Direction.SENT;
        msg.chatid = chatId;
        final Message finalMsg = msg;
        new Thread(new Runnable() {
            @Override
            public void run() {
                DatabaseManager.messageDAO().insert(finalMsg);
            }
        }).start();
        tv.setText(tv.getText()+"\n"+msg.toString());

    }

}
