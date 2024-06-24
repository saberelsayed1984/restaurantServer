const express = require('express');
const {body} = require('express-validator');
const router = express.Router();
const foodController = require('../Controllers/foodControl');
router.route('/food')
            .get( foodController.getAllFood)
            .post( body (), foodController.addFood,[
                body('title')
                    .notEmpty()
                    .withMessage("title is empty")
                    .isLength({min:2})
                    .withMessage("title is dont less 2"),
                body('description')
                .notEmpty()
                .withMessage("description is empty")
                .isLength({min:2})
                .withMessage("description is dont less 2"),    
                body('price')
                    .notEmpty()
                    .withMessage("price is required")
                    
                ]);
                router.route('/:foodId')
                .get( foodController.getFood)
                .patch( foodController.updateFood, 
                    [ body('title')
                    .notEmpty()
                    .withMessage("title is empty")
                    .isLength({min:2})
                    .withMessage("title is dont less 2"),
                body('description')
                .notEmpty()
                .withMessage("description is empty")
                .isLength({min:2})
                .withMessage("description is dont less 2"),    
                body('price')
                    .notEmpty()
                    .withMessage("price is required")
                    
                        
                    ])
                .delete(foodController.delateFood)
    module.exports = router;