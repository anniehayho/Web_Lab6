require("dotenv").config();
const amqp = require("amqplib");
const { faker } = require("@faker-js/faker");


async function sendMessages() {
  try {
    const connection = await amqp.connect(process.env.RABBITMQ_URL);
    const channel = await connection.createChannel();

    const queue = process.env.QUEUE_NAME;
    await channel.assertQueue(queue);

    setInterval(() => {
      const message = {
        producer: "Producer 2",
        data: faker.internet.email(),
        timestamp: new Date(),
      };
      channel.sendToQueue(queue, Buffer.from(JSON.stringify(message)));
      console.log(`[Producer 2] Sent:`, message);
    }, 5000);

    process.on("exit", () => {
      channel.close();
      console.log("Producer 2 channel closed.");
    });
  } catch (error) {
    console.error("[Producer 2] Error:", error);
  }
}

sendMessages();
