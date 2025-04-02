import { NestFactory } from "@nestjs/core";
import { ValidationPipe } from "@nestjs/common";
import { SwaggerModule, DocumentBuilder } from "@nestjs/swagger";
import { AppModule } from "./app.module";
import { WinstonModule } from "nest-winston";
import * as winston from "winston";
import * as bodyParser from "body-parser";

async function bootstrap() {
  // Print environment variables
  console.log("Environment Variables:");
  console.log(`SUPABASE_URL: ${process.env.SUPABASE_URL}`);
  console.log(`SUPABASE_ANON_KEY: ${process.env.SUPABASE_ANON_KEY}`);
  console.log(`SUPABASE_SERVICE_KEY: ${process.env.SUPABASE_SERVICE_KEY}`);
  console.log(`MOBSF_API_KEY: ${process.env.MOBSF_API_KEY}`);
  console.log(`MOBSF_API_URL: ${process.env.MOBSF_API_URL}`);
  console.log(`REDIS_HOST: ${process.env.REDIS_HOST}`);
  console.log(`REDIS_PORT: ${process.env.REDIS_PORT}`);
  console.log(`VIRUSTOTAL_API_KEY: ${process.env.VIRUSTOTAL_API_KEY}`);
  console.log(`METADEFENDER_API_KEY: ${process.env.METADEFENDER_API_KEY}`);
  console.log(
    `HYBRID_ANALYSIS_API_KEY: ${process.env.HYBRID_ANALYSIS_API_KEY}`
  );

  // Configure Winston logger
  const logger = WinstonModule.createLogger({
    transports: [
      new winston.transports.Console({
        format: winston.format.combine(
          winston.format.timestamp(),
          winston.format.colorize(),
          winston.format.printf(({ timestamp, level, message }) => {
            return `${timestamp} [${level}]: ${message}`;
          })
        ),
        level: "debug",
      }),
      new winston.transports.File({
        filename: "logs/error.log",
        level: "debug",
        format: winston.format.combine(
          winston.format.timestamp(),
          winston.format.json()
        ),
      }),
      new winston.transports.File({
        filename: "logs/combined.log",
        format: winston.format.combine(
          winston.format.timestamp(),
          winston.format.json()
        ),
      }),
    ],
  });

  const app = await NestFactory.create(AppModule, { logger });

  // Increase the body size limit
  app.use(bodyParser.json({ limit: "100mb" }));
  app.use(bodyParser.urlencoded({ limit: "100mb", extended: true }));

  // Enable CORS
  app.enableCors({
    origin: "http://localhost:3000",
    methods: "GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS",
    allowedHeaders: "Content-Type, Authorization",
  });

  // Enable validation pipes
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      transform: true,
      forbidNonWhitelisted: true,
    })
  );

  // Setup Swagger
  const config = new DocumentBuilder()
    .setTitle("TrustForge API")
    .setDescription("Mobile App Security Analysis Platform API")
    .setVersion("1.0")
    .addBearerAuth()
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup("api", app, document);

  await app.listen(3001);
}
bootstrap();
