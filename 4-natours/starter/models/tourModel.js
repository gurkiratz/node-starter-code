const mongoose = require('mongoose');
const slugify = require('slugify');

const opts = { toJSON: { virtuals: true }, toObject: { virtuals: true } };
const tourSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, 'A tour must have a name'],
      unique: true,
      trim: true,
    },
    slug: String,
    duration: { type: Number, required: [true, 'A tour must have a duration'] },
    maxGroupSize: {
      type: Number,
      required: [true, 'A tour must have a group size'],
    },
    difficulty: {
      type: String,
      required: [true, 'A tour must have a difficulty'],
    },
    ratingsAverage: { type: Number, default: 4.5 },
    ratingsQuantity: { type: Number, default: 0 },
    priceDiscount: Number,
    summary: { type: String, trim: true },
    description: {
      type: String,
      trim: true,
      required: [true, 'A tour must have a description'],
    },
    imageCover: {
      type: String,
      required: [true, 'A tour must have a cover image'],
    },
    images: [String],
    createdAt: { type: Date, default: Date.now(), select: false },
    startDates: [Date],
  },
  opts
);

// DOCUMENT MIDDLEWARE: runs  before .save() and .create()
tourSchema.pre('save', function (next) {
  this.slug = slugify(this.name, { lower: true });
  next();
});

// tourSchema.pre('save', function (next) {
//   console.log('this is pre');
//   next();
// });

// tourSchema.post('save', function (doc, next) {
//   console.log(doc.name, doc.slug);
//   next();
// });

tourSchema.virtual('numberOfWeeks').get(function () {
  if (this.duration < 7) {
    return `${this.duration} days`;
  }
  return this.duration / 7;
});

const Tour = mongoose.model('Tour', tourSchema);

module.exports = Tour;
