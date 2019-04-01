package de.finnsweb.quantum.ui;

import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.os.AsyncTask;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ImageView;
import android.widget.TextView;

import java.io.InputStream;
import java.util.List;

import androidx.annotation.NonNull;
import androidx.recyclerview.widget.RecyclerView;
import de.finnsweb.quantum.R;
import de.finnsweb.quantum.storage.Chat;

public class ChatListAdapter extends RecyclerView.Adapter {

    private List<Chat> chats;
    private RecyclerView recyclerView;
    private Context context;

    public ChatListAdapter (List<Chat> chats, RecyclerView recyclerView, Context context){
        this.chats = chats;
        this.recyclerView = recyclerView;
        this.context = context;
    }

    @NonNull
    @Override
    public RecyclerView.ViewHolder onCreateViewHolder(@NonNull ViewGroup parent, int viewType) {
        View view = LayoutInflater.from(parent.getContext()).inflate(R.layout.chat_list_element, parent, false);
        view.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                Intent intent = new Intent(context,ChatActivity.class);
                intent.putExtra("de.finnsweb.quantum.ui.chatid",chats.get(recyclerView.getChildAdapterPosition(view)).id);
                context.startActivity(intent);
            }
        });
        return new ChatViewHolder(view);
    }

    @Override
    public void onBindViewHolder(@NonNull RecyclerView.ViewHolder holder, int position) {
        Chat chat = chats.get(position);
        ((ChatViewHolder)holder).bind(chat);
    }

    @Override
    public int getItemCount() {
        return chats.size();
    }

    private class ChatViewHolder extends RecyclerView.ViewHolder {

        RoundedImageView chatPictureView;
        TextView chatTitleText;
        TextView lastMessageText;

        public ChatViewHolder(@NonNull View itemView) {
            super(itemView);
            chatPictureView = itemView.findViewById(R.id.chatPictureView);
            chatTitleText = itemView.findViewById(R.id.chatTitleView);
            lastMessageText = itemView.findViewById(R.id.lastMessageView);
        }

        void bind(Chat chat){
            //TODO: Profile pic https://developer.android.com/training/data-storage/files
            chatTitleText.setText(chat.title);
            lastMessageText.setText(chat.lastMessage);
        }
    }

    public void addChat(Chat chat){
        chats.add(chat);
        notifyItemInserted(getItemCount());
    }
}
