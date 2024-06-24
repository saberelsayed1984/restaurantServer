const Food = require('../models/foodModel');
const { validationResult } = require('express-validator');
const asyncWrapper = require('./asyncWrapper');
const addFood = asyncWrapper(async (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(500).json({ error: errors.array() });
    }
    
        const newFood = new Food(req.body);
        await newFood.save();
        res.status(201).json({data:{food: newFood}});}
    )
const getAllFood = asyncWrapper(async(req, res, next) => {
    const query = req.query;
    const limit = query.limit || 4;
    const page = query.page || 1;
    const skip = (page - 1) * limit;
    const food = await Food.find({}, {
        // "__v":false, "_id":0
    }).limit(limit).skip(skip);
    res.json({data:{food}});});
const getFood = asyncWrapper( async(req, res) => {  
    const food = await Food.findById(req.params.foodId);
        if (!food) {
            return res.status(500).json({ error: errors.array() });
        }
    res.json({data:{food}});

} );    
const updateFood =  asyncWrapper(async (req, res) => {
    const foodId = req.params.foodId; 
    const updateFood = await Food.updateOne({_id: foodId}, {$set:{...req.body}});
    return res.status(200).json({  msg:"update succesfully" })

    // return res.status(200).json({data:{updateFood}})})
    // await User.updateOne({_id: userId}, {$set:{...req.body}});
    return res.status(200).json({  msg:"update succesfully" })})
const delateFood = asyncWrapper(async (req,res) => {
    await Food.deleteOne ({_id: req.params.foodId});
res.status(200).json({data: null});
});
    module.exports = {addFood,
        getAllFood,getFood,
        updateFood,
        delateFood
    }