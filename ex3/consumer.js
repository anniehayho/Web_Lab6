require("dotenv").config();
const amqp = require("amqplib");
const mongoose = require("mongoose");

const messageSchema = new mongoose.Schema({
  producer: String,
  data: String,
  timestamp: Date,
});
const Message = mongoose.model("Message", messageSchema);

async function consumeMessages() {
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
    });
    console.log("Connected to MongoDB.");

    // Connect to RabbitMQ
    const connection = await amqp.connect(process.env.RABBITMQ_URL);
    const channel = await connection.createChannel();

    const queue = process.env.QUEUE_NAME;
    await channel.assertQueue(queue);

    console.log(`Waiting for messages in queue: ${queue}`);

    channel.consume(
      queue,
      async (msg) => {
        if (msg) {
          const message = JSON.parse(msg.content.toString());
          console.log(`[Consumer] Received:`, message);

          // Save to MongoDB
          const savedMessage = new Message(message);
          await savedMessage.save();
          console.log(`[Consumer] Saved to MongoDB:`, savedMessage);

          // Acknowledge the message
          channel.ack(msg);
        }
      },
      { noAck: false }
    );

    process.on("exit", () => {
      channel.close();
      console.log("Consumer channel closed.");
    });
  } catch (error) {
    console.error("[Consumer] Error:", error);
  }
}

consumeMessages();
