/*
 * Policy Engine I/O Formats
 *
 * Documentation for the input and output formats used in Policy Engine
 *
 * API version: 1.0.0
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package models

// Points to a row and column within a source file
type SourceLocation struct {
	Filepath string `json:"filepath,omitempty"`
	Line     int    `json:"line,omitempty"`
	Column   int    `json:"column,omitempty"`
}