const mongoose = require("mongoose");

const sectionSchema = new mongoose.Schema({
    sectionname:{
        type:String
    },
    subsection:{
        {
            type:mongoose.Schema.Types.ObjectId,
            required:true,
            ref:"SubSection"
        }
    }
})

module.exports = mongoose.model("Section", sectionSchema);