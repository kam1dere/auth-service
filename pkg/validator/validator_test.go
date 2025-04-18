package validator

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

type TestStruct struct {
	RequiredField string `validate:"required"`
	TagField      string `validate:"tag"`
	MaxField      string `validate:"max=5"`
	MinField      string `validate:"min=3"`
	LtField       int    `validate:"lt=10"`
	GteField      int    `validate:"gte=5"`
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name       string
		input      TestStruct
		wantErr    bool
		wantErrMsg string
	}{
		{
			name:       "Valid struct",
			input:      TestStruct{RequiredField: "value", TagField: "#tag", MaxField: "value", MinField: "val", LtField: 5, GteField: 5},
			wantErr:    false,
			wantErrMsg: "",
		},
		{
			name:       "Missing required field",
			input:      TestStruct{TagField: "#tag", MaxField: "value", MinField: "val", LtField: 5, GteField: 5},
			wantErr:    true,
			wantErrMsg: ErrFieldRequired + ": TestStruct.RequiredField",
		},
		{
			name:       "Invalid tag field",
			input:      TestStruct{RequiredField: "value", TagField: "tag", MaxField: "value", MinField: "val", LtField: 5, GteField: 5},
			wantErr:    true,
			wantErrMsg: ErrInvalidFormat + ": TestStruct.TagField",
		},
		{
			name:       "Field exceeds max length",
			input:      TestStruct{RequiredField: "value", TagField: "#tag", MaxField: "toolong", MinField: "val", LtField: 5, GteField: 5},
			wantErr:    true,
			wantErrMsg: ErrFieldExceedsMaxLen + ": TestStruct.MaxField",
		},
		{
			name:       "Field below min length",
			input:      TestStruct{RequiredField: "value", TagField: "#tag", MaxField: "value", MinField: "va", LtField: 5, GteField: 5},
			wantErr:    true,
			wantErrMsg: ErrFieldBelowMinLen + ": TestStruct.MinField",
		},
		{
			name:       "Field exceeds max value",
			input:      TestStruct{RequiredField: "value", TagField: "#tag", MaxField: "value", MinField: "val", LtField: 15, GteField: 5},
			wantErr:    true,
			wantErrMsg: ErrFieldExceedsMaxVal + ": TestStruct.LtField",
		},
		{
			name:       "Field below min value",
			input:      TestStruct{RequiredField: "value", TagField: "#tag", MaxField: "value", MinField: "val", LtField: 5, GteField: 3},
			wantErr:    true,
			wantErrMsg: ErrFieldBelowMinVal + ": TestStruct.GteField",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(context.Background(), tt.input)
			if tt.wantErr {
				assert.NotNil(t, err)
				assert.EqualError(t, err, tt.wantErrMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
