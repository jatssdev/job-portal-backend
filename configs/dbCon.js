const mongoose = require('mongoose')

const mongodbCon = async (URL) => {
  await mongoose.connect(URL)
  console.log("Database COnnected");
}

module.exports = { mongodbCon }