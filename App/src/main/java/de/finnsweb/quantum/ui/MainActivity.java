package de.finnsweb.quantum.ui;

import androidx.appcompat.app.AppCompatActivity;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;
import androidx.room.Database;
import de.finnsweb.quantum.R;
import de.finnsweb.quantum.storage.Chat;
import de.finnsweb.quantum.storage.DatabaseManager;
import de.finnsweb.quantum.ui.ChatListAdapter;

import android.content.Context;
import android.os.Bundle;
import android.view.View;

import com.google.android.material.floatingactionbutton.FloatingActionButton;

import java.util.ArrayList;
import java.util.List;

public class MainActivity extends AppCompatActivity {

    ChatListAdapter chatListAdapter;
    Context context;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        context = this;

        new Thread(new Runnable() {
            @Override
            public void run() {
                final List<Chat> chats = DatabaseManager.chatDAO().getAllChats();
                runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        RecyclerView recyclerView =  findViewById(R.id.chatListRecyclerView);
                        recyclerView.setLayoutManager(new LinearLayoutManager(context));
                        chatListAdapter = new ChatListAdapter(chats, recyclerView, context);
                        recyclerView.setAdapter(chatListAdapter);
                    }
                });
            }
        }).start();



        FloatingActionButton fab = findViewById(R.id.newChatButton);
        fab.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                new Thread(new Runnable() {
                    @Override
                    public void run() {
                        Chat chat = new Chat();
                        chat.title = "Another awesome chat";
                        chat.lastMessage = "...";
                        chat.id = DatabaseManager.chatDAO().insert(chat);
                        final Chat finalChat = chat;
                        runOnUiThread(new Runnable() {
                            @Override
                            public void run() {
                                chatListAdapter.addChat(finalChat);
                            }
                        });
                    }
                }).start();

            }
        });
    }
}
