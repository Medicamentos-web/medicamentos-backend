FROM node:20-alpine

WORKDIR /app

RUN apk add --no-cache tesseract-ocr tesseract-ocr-data-deu tesseract-ocr-data-eng poppler-utils

COPY package.json package-lock.json* ./
RUN npm install --omit=dev

COPY . .

EXPOSE 4000

CMD ["npm", "start"]
